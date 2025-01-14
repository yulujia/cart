/* Copyright (c) 2016 UChicago Argonne, LLC
 * Copyright (C) 2018-2019 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for any purpose (including commercial purposes)
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions, and the following disclaimer in the
 *    documentation and/or materials provided with the distribution.
 *
 * 3. In addition, redistributions of modified forms of the source or binary
 *    code must carry prominent notices stating that the original code was
 *    changed and the date of the change.
 *
 * 4. All publications or advertising materials mentioning features or use of
 *    this software are asked, but not required, to acknowledge that it was
 *    developed by Intel Corporation and credit the contributors.
 *
 * 5. Neither the name of Intel Corporation, nor the name of any Contributor
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define D_LOGFAC	DD_FAC(swim)

#include "swim_internal.h"
#include <assert.h>

static uint64_t swim_ping_timeout = SWIM_PING_TIMEOUT;

static inline void
swim_dump_updates(swim_id_t self_id, swim_id_t from, swim_id_t to,
		  struct swim_member_update *upds, size_t nupds)
{
	FILE *fp;
	char *msg;
	size_t msg_size, i;
	int rc;

	if (!D_LOG_ENABLED(DLOG_INFO))
		return;

	fp = open_memstream(&msg, &msg_size);
	if (fp != NULL) {
		for (i = 0; i < nupds; i++) {
			rc = fprintf(fp, " {%lu %c %lu}", upds[i].smu_id,
				     "ASD"[upds[i].smu_state.sms_status],
				     upds[i].smu_state.sms_incarnation);
			if (rc < 0)
				break;
		}

		fclose(fp);
		/* msg and msg_size will be set after fclose(fp) only */
		if (msg_size > 0)
			SWIM_INFO("%lu %s %lu:%s\n", self_id,
				  self_id == from ? "=>" : "<=",
				  self_id == from ? to   : from, msg);
		free(msg); /* allocated by open_memstream() */
	}
}

static int
swim_updates_send(struct swim_context *ctx, swim_id_t id, swim_id_t to)
{
	struct swim_member_update *upds;
	struct swim_item *next, *item;
	swim_id_t self_id = swim_self_get(ctx);
	size_t nupds, i = 0;
	int rc = 0;

	if (id == SWIM_ID_INVALID || to == SWIM_ID_INVALID) {
		SWIM_ERROR("member id is invalid\n");
		D_GOTO(out, rc = -EINVAL);
	}

	nupds = SWIM_PIGGYBACK_ENTRIES + (id != self_id ? 2 : 1);
	D_ALLOC_ARRAY(upds, nupds);
	if (upds == NULL)
		D_GOTO(out, rc = -ENOMEM);

	swim_ctx_lock(ctx);

	rc = ctx->sc_ops->get_member_state(ctx, id, &upds[i].smu_state);
	if (rc) {
		SWIM_ERROR("get_member_state() failed rc=%d\n", rc);
		D_GOTO(out_unlock, rc);
	}
	upds[i++].smu_id = id;

	if (id != self_id) {
		/* update self status on target */
		rc = ctx->sc_ops->get_member_state(ctx, self_id,
						   &upds[i].smu_state);
		if (rc) {
			SWIM_ERROR("get_member_state() failed rc=%d\n", rc);
			D_GOTO(out_unlock, rc);
		}
		upds[i++].smu_id = self_id;
	}

	item = TAILQ_FIRST(&ctx->sc_updates);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);

		/* delete entries that are too many */
		if (i >= nupds) {
			TAILQ_REMOVE(&ctx->sc_updates, item, si_link);
			D_FREE(item);
			item = next;
			continue;
		}

		/* update with recent updates */
		if (item->si_id != id && item->si_id != self_id) {
			rc = ctx->sc_ops->get_member_state(ctx, item->si_id,
							   &upds[i].smu_state);
			if (rc) {
				if (rc == -DER_NONEXIST) {
					/* this member was removed already */
					TAILQ_REMOVE(&ctx->sc_updates, item,
						     si_link);
					D_FREE(item);
					item = next;
					continue;
				}
				SWIM_ERROR("get_member_state() failed rc=%d\n",
					   rc);
				D_GOTO(out_unlock, rc);
			}
			upds[i++].smu_id = item->si_id;
		}

		if (++item->u.si_count > ctx->sc_piggyback_tx_max) {
			TAILQ_REMOVE(&ctx->sc_updates, item, si_link);
			D_FREE(item);
		}

		item = next;
	}
	rc = 0;

out_unlock:
	swim_ctx_unlock(ctx);

	if (rc == 0) {
		swim_dump_updates(self_id, self_id, to, upds, i);
		rc = ctx->sc_ops->send_message(ctx, to, upds, i);
	}

	if (rc)
		D_FREE(upds);
out:
	return rc;
}

static int
swim_updates_notify(struct swim_context *ctx, swim_id_t from, swim_id_t id,
		    struct swim_member_state *id_state)
{
	struct swim_item *item;

	/* determine if this member already have an update */
	TAILQ_FOREACH(item, &ctx->sc_updates, si_link) {
		if (item->si_id == id) {
			item->si_from = from;
			item->u.si_count = 0;
			D_GOTO(update, 0);
		}
	}

	/* add this update to recent update list so it will be
	 * piggybacked on future protocol messages
	 */
	D_ALLOC_PTR(item);
	if (item != NULL) {
		item->si_id   = id;
		item->si_from = from;
		item->u.si_count = 0;
		TAILQ_INSERT_HEAD(&ctx->sc_updates, item, si_link);
	}
update:
	return ctx->sc_ops->set_member_state(ctx, id, id_state);
}

static int
swim_member_alive(struct swim_context *ctx, swim_id_t from,
		  swim_id_t id, uint64_t nr)
{
	struct swim_member_state id_state;
	struct swim_item *item;
	int rc;

	rc = ctx->sc_ops->get_member_state(ctx, id, &id_state);
	if (rc) {
		SWIM_ERROR("get_member_state() failed rc=%d\n", rc);
		D_GOTO(out, rc);
	}

	if (nr > id_state.sms_incarnation)
		D_GOTO(update, rc);

	/* ignore old updates or updates for dead members */
	if (id_state.sms_status == SWIM_MEMBER_DEAD ||
	    id_state.sms_status == SWIM_MEMBER_ALIVE ||
	    id_state.sms_incarnation > nr)
		D_GOTO(out, rc = -EALREADY);

update:
	/* if member is suspected, remove from suspect list */
	TAILQ_FOREACH(item, &ctx->sc_suspects, si_link) {
		if (item->si_id == id) {
			/* remove this member from suspect list */
			TAILQ_REMOVE(&ctx->sc_suspects, item, si_link);
			if (swim_ping_timeout < SWIM_PROTOCOL_PERIOD_LEN) {
				swim_ping_timeout += SWIM_PING_TIMEOUT;
				SWIM_INFO("%lu: increase ping timeout to %lu\n",
					  ctx->sc_self, swim_ping_timeout);
			}
			D_FREE(item);
			break;
		}
	}

	id_state.sms_incarnation = nr;
	id_state.sms_status = SWIM_MEMBER_ALIVE;
	rc = swim_updates_notify(ctx, from, id, &id_state);
out:
	return rc;
}

static int
swim_member_dead(struct swim_context *ctx, swim_id_t from,
		 swim_id_t id, uint64_t nr)
{
	struct swim_member_state id_state;
	struct swim_item *item;
	int rc;

	rc = ctx->sc_ops->get_member_state(ctx, id, &id_state);
	if (rc) {
		SWIM_ERROR("get_member_state() failed rc=%d\n", rc);
		D_GOTO(out, rc);
	}

	if (nr > id_state.sms_incarnation)
		D_GOTO(update, rc);

	/* ignore old updates or updates for dead members */
	if (id_state.sms_status == SWIM_MEMBER_DEAD ||
	    id_state.sms_incarnation > nr)
		D_GOTO(out, rc = -EALREADY);

update:
	/* if member is suspected, remove it from suspect list */
	TAILQ_FOREACH(item, &ctx->sc_suspects, si_link) {
		if (item->si_id == id) {
			/* remove this member from suspect list */
			TAILQ_REMOVE(&ctx->sc_suspects, item, si_link);
			D_FREE(item);
			break;
		}
	}

	id_state.sms_incarnation = nr;
	id_state.sms_status = SWIM_MEMBER_DEAD;
	rc = swim_updates_notify(ctx, from, id, &id_state);
out:
	return rc;
}

static int
swim_member_suspect(struct swim_context *ctx, swim_id_t from,
		    swim_id_t id, uint64_t nr)
{
	struct swim_member_state id_state;
	struct swim_item *item;
	int rc;

	/* if there is no suspicion timeout, just kill the member */
	if (SWIM_SUSPECT_TIMEOUT == 0)
		return swim_member_dead(ctx, from, id, nr);

	rc = ctx->sc_ops->get_member_state(ctx, id, &id_state);
	if (rc) {
		SWIM_ERROR("get_member_state() failed rc=%d\n", rc);
		D_GOTO(out, rc);
	}

	if (nr > id_state.sms_incarnation)
		D_GOTO(search, rc);

	/* ignore old updates or updates for dead members */
	if (id_state.sms_status == SWIM_MEMBER_DEAD ||
	    id_state.sms_status == SWIM_MEMBER_SUSPECT ||
	    id_state.sms_incarnation > nr)
		D_GOTO(out, rc = -EALREADY);

search:
	/* determine if this member is already suspected */
	TAILQ_FOREACH(item, &ctx->sc_suspects, si_link) {
		if (item->si_id == id)
			D_GOTO(update, rc);
	}

	/* add to end of suspect list */
	D_ALLOC_PTR(item);
	if (item == NULL)
		D_GOTO(out, rc = -ENOMEM);
	item->si_id = id;
	item->si_from = from;
	item->u.si_deadline = swim_now_ms() + SWIM_SUSPECT_TIMEOUT;
	TAILQ_INSERT_TAIL(&ctx->sc_suspects, item, si_link);

update:
	id_state.sms_incarnation = nr;
	id_state.sms_status = SWIM_MEMBER_SUSPECT;
	rc = swim_updates_notify(ctx, from, id, &id_state);
out:
	return rc;
}

static int
swim_member_update_suspected(struct swim_context *ctx, uint64_t now)
{
	TAILQ_HEAD(, swim_item)  targets;
	struct swim_member_state id_state;
	struct swim_item *next, *item;
	swim_id_t self_id = swim_self_get(ctx);
	swim_id_t id, from;
	int rc = 0;

	TAILQ_INIT(&targets);

	/* update status of suspected members */
	swim_ctx_lock(ctx);
	item = TAILQ_FIRST(&ctx->sc_suspects);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		if (now > item->u.si_deadline) {
			SWIM_INFO("%lu: suspect timeout %lu\n",
				  self_id, item->si_id);

			if (item->si_from != self_id) {
				/* let's try to confirm from gossip origin */
				id   = item->si_id;
				from = item->si_from;

				item->si_from = self_id;
				item->u.si_deadline += swim_ping_timeout;

				D_ALLOC_PTR(item);
				if (item == NULL)
					D_GOTO(next_item, rc = -ENOMEM);
				item->si_id   = id;
				item->si_from = from;
				TAILQ_INSERT_TAIL(&targets, item, si_link);
			} else {
				rc = ctx->sc_ops->get_member_state(ctx,
								   item->si_id,
								   &id_state);
				if (!rc) {
					/* if this member has exceeded
					 * its allowable suspicion timeout,
					 * we mark it as dead
					 */
					swim_member_dead(ctx, item->si_from,
							item->si_id,
						      id_state.sms_incarnation);
				} else {
					TAILQ_REMOVE(&ctx->sc_suspects, item,
						     si_link);
					D_FREE(item);
				}
			}
		}
next_item:
		item = next;
	}
	swim_ctx_unlock(ctx);

	/* send confirmations to selected members */
	item = TAILQ_FIRST(&targets);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		SWIM_INFO("%lu: try to confirm %lu <= %lu\n", self_id,
			  item->si_id, item->si_from);

		rc = swim_updates_send(ctx, item->si_id, item->si_from);
		if (rc)
			SWIM_ERROR("swim_updates_send() failed rc=%d\n", rc);

		D_FREE(item);
		item = next;
	}

	return rc;
}

static int
swim_ipings_update(struct swim_context *ctx, uint64_t now)
{
	struct swim_item *next, *item;
	int rc = 0;

	swim_ctx_lock(ctx);
	item = TAILQ_FIRST(&ctx->sc_ipings);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		if (now > item->u.si_deadline) {
			TAILQ_REMOVE(&ctx->sc_ipings, item, si_link);
			D_FREE(item);
		}
		item = next;
	}
	swim_ctx_unlock(ctx);

	return rc;
}

static int
swim_subgroup_init(struct swim_context *ctx)
{
	struct swim_item *item;
	swim_id_t id;
	int i, rc = 0;

	for (i = 0; i < SWIM_SUBGROUP_SIZE; i++) {
		id = ctx->sc_ops->get_iping_target(ctx);
		if (id == SWIM_ID_INVALID)
			D_GOTO(out, rc = 0);

		D_ALLOC_PTR(item);
		if (item == NULL)
			D_GOTO(out, rc = -ENOMEM);
		item->si_id = id;
		TAILQ_INSERT_TAIL(&ctx->sc_subgroup, item, si_link);
	}
out:
	return rc;
}

void *
swim_data(struct swim_context *ctx)
{
	return ctx ? ctx->sc_data : NULL;
}

swim_id_t
swim_self_get(struct swim_context *ctx)
{
	return ctx ? ctx->sc_self : SWIM_ID_INVALID;
}

void
swim_self_set(struct swim_context *ctx, swim_id_t self_id)
{
	if (ctx != NULL)
		ctx->sc_self = self_id;
}

struct swim_context *
swim_init(swim_id_t self_id, struct swim_ops *swim_ops, void *data)
{
	struct swim_context *ctx;
	int rc;

	if (swim_ops == NULL ||
	    swim_ops->send_message == NULL ||
	    swim_ops->get_dping_target == NULL ||
	    swim_ops->get_iping_target == NULL ||
	    swim_ops->get_member_state == NULL ||
	    swim_ops->set_member_state == NULL) {
		SWIM_ERROR("there are no proper callbacks specified\n");
		D_GOTO(out, ctx = NULL);
	}

	/* allocate structure for storing swim context */
	D_ALLOC_PTR(ctx);
	if (ctx == NULL)
		D_GOTO(out, ctx = NULL);
	memset(ctx, 0, sizeof(*ctx));

	rc = SWIM_MUTEX_CREATE(ctx->sc_mutex, NULL);
	if (rc != 0) {
		D_FREE(ctx);
		SWIM_ERROR("SWIM_MUTEX_CREATE() failed rc=%d\n", rc);
		D_GOTO(out, ctx = NULL);
	}

	ctx->sc_self = self_id;
	ctx->sc_data = data;
	ctx->sc_ops  = swim_ops;

	TAILQ_INIT(&ctx->sc_subgroup);
	TAILQ_INIT(&ctx->sc_suspects);
	TAILQ_INIT(&ctx->sc_updates);
	TAILQ_INIT(&ctx->sc_ipings);

	/* this can be tuned according members count */
	ctx->sc_piggyback_tx_max = SWIM_PIGGYBACK_TX_COUNT;
	/* force to choose next target first */
	ctx->sc_target = SWIM_ID_INVALID;
out:
	return ctx;
}

void
swim_fini(struct swim_context *ctx)
{
	struct swim_item *next, *item;

	if (ctx == NULL)
		return;

	item = TAILQ_FIRST(&ctx->sc_ipings);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		TAILQ_REMOVE(&ctx->sc_ipings, item, si_link);
		D_FREE(item);
		item = next;
	}

	item = TAILQ_FIRST(&ctx->sc_updates);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		TAILQ_REMOVE(&ctx->sc_updates, item, si_link);
		D_FREE(item);
		item = next;
	}

	item = TAILQ_FIRST(&ctx->sc_suspects);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		TAILQ_REMOVE(&ctx->sc_suspects, item, si_link);
		D_FREE(item);
		item = next;
	}

	item = TAILQ_FIRST(&ctx->sc_subgroup);
	while (item != NULL) {
		next = TAILQ_NEXT(item, si_link);
		TAILQ_REMOVE(&ctx->sc_subgroup, item, si_link);
		D_FREE(item);
		item = next;
	}

	SWIM_MUTEX_DESTROY(ctx->sc_mutex);

	D_FREE(ctx);
}

int
swim_progress(struct swim_context *ctx, int64_t timeout)
{
	enum swim_context_state ctx_state = SCS_TIMEDOUT;
	struct swim_member_state target_state;
	struct swim_item *item;
	uint64_t now, end = 0;
	swim_id_t id_target, id_sendto;
	bool send_updates = false;
	int rc;

	/* validate input parameters */
	if (ctx == NULL) {
		SWIM_ERROR("invalid parameter (ctx is NULL)\n");
		D_GOTO(out, rc = -EINVAL);
	}

	if (ctx->sc_self == SWIM_ID_INVALID) /* not initialized yet */
		D_GOTO(out, rc = 0); /* Ignore this update */

	now = swim_now_ms();
	if (timeout > 0)
		end = now + timeout;

	for (; now <= end || ctx_state == SCS_TIMEDOUT; now = swim_now_ms()) {
		rc = swim_member_update_suspected(ctx, now);
		if (rc) {
			SWIM_ERROR("swim_member_update_suspected() failed "
				   "rc=%d\n", rc);
			D_GOTO(out, rc);
		}

		rc = swim_ipings_update(ctx, now);
		if (rc) {
			SWIM_ERROR("swim_ipings_update() failed rc=%d\n", rc);
			D_GOTO(out, rc);
		}

		swim_ctx_lock(ctx);
		ctx_state = SCS_DEAD;
		if (ctx->sc_target != SWIM_ID_INVALID) {
			rc = ctx->sc_ops->get_member_state(ctx,
							   ctx->sc_target,
							   &target_state);
			if (rc) {
				ctx->sc_target = SWIM_ID_INVALID;
				if (rc != -DER_NONEXIST) {
					swim_ctx_unlock(ctx);
					SWIM_ERROR("get_member_state() "
						   "failed rc=%d\n", rc);
					D_GOTO(out, rc);
				}
			} else {
				ctx_state = swim_state_get(ctx);
			}
		}

		switch (ctx_state) {
		case SCS_BEGIN:
			if (now > ctx->sc_next_tick_time) {
				ctx->sc_next_tick_time = now
						     + SWIM_PROTOCOL_PERIOD_LEN;

				id_target = ctx->sc_target;
				id_sendto = ctx->sc_target;
				send_updates = true;
				SWIM_INFO("%lu: dping %lu => %lu\n",
					 ctx->sc_self, ctx->sc_self, id_sendto);

				ctx->sc_dping_deadline = now
							+ swim_ping_timeout;
				ctx_state = SCS_DPINGED;
			}
			break;
		case SCS_DPINGED:
			/* check whether the ping target from the previous
			 * protocol tick ever successfully acked a direct
			 * ping request
			 */
			if (now > ctx->sc_dping_deadline) {
				/* no response from direct pings,
				 * suspect this member
				 */
				swim_member_suspect(ctx, ctx->sc_self,
						    ctx->sc_target,
						  target_state.sms_incarnation);
				ctx_state = SCS_TIMEDOUT;
			}
			break;
		case SCS_IPINGED:
			/* check whether the ping target from the previous
			 * protocol tick ever successfully acked a indirect
			 * ping request
			 */
			if (now > ctx->sc_iping_deadline) {
				/* no response from indirect pings,
				 * dead this member
				 */
				SWIM_INFO("%lu: iping timeout %lu\n",
					  ctx->sc_self, ctx->sc_target);

				swim_member_dead(ctx, ctx->sc_self,
						 ctx->sc_target,
						 target_state.sms_incarnation);
				ctx_state = SCS_DEAD;
			}
			break;
		case SCS_TIMEDOUT:
			/* if we don't hear back from the target after an RTT,
			 * kick off a set of indirect pings to a subgroup of
			 * group members
			 */
			item = TAILQ_FIRST(&ctx->sc_subgroup);
			if (item == NULL) {
				rc = swim_subgroup_init(ctx);
				if (rc) {
					swim_ctx_unlock(ctx);
					SWIM_ERROR("swim_subgroup_init() "
						   "failed rc=%d\n", rc);
					D_GOTO(out, rc);
				}
				item = TAILQ_FIRST(&ctx->sc_subgroup);
			}

			if (item != NULL) {
				id_target = ctx->sc_target;
				id_sendto = item->si_id;
				send_updates = true;

				SWIM_INFO("%lu: ireq  %lu => %lu\n",
					  ctx->sc_self, id_sendto, id_target);

				TAILQ_REMOVE(&ctx->sc_subgroup,
					     item, si_link);
				D_FREE(item);

				item = TAILQ_FIRST(&ctx->sc_subgroup);
				if (item == NULL) {
					ctx->sc_iping_deadline = now
							+ 2 * swim_ping_timeout;
					ctx_state = SCS_IPINGED;
				}
				break;
			}
			/* fall through to select a next target */
		case SCS_ACKED:
		case SCS_DEAD:
			ctx->sc_target = ctx->sc_ops->get_dping_target(ctx);
			if (ctx->sc_target == SWIM_ID_INVALID) {
				swim_ctx_unlock(ctx);
				D_GOTO(out, rc = -ESHUTDOWN);
			}

			ctx_state = SCS_BEGIN;
			break;
		}

		swim_state_set(ctx, ctx_state);
		swim_ctx_unlock(ctx);

		if (send_updates) {
			rc = swim_updates_send(ctx, id_target, id_sendto);
			if (rc) {
				SWIM_ERROR("swim_updates_send() failed rc=%d\n",
					   rc);
				D_GOTO(out, rc);
			}
			send_updates = false;
		}
	}
	rc = (now > end) ? -ETIMEDOUT : -EINTR;
out:
	return rc;
}

int
swim_parse_message(struct swim_context *ctx, swim_id_t from,
		   struct swim_member_update *upds, size_t nupds)
{
	struct swim_item *item;
	enum swim_context_state ctx_state;
	struct swim_member_state self_state;
	swim_id_t self_id = swim_self_get(ctx);
	swim_id_t id_target, id_sendto, to;
	bool send_updates = false;
	size_t i;
	int rc = 0;

	if (self_id == SWIM_ID_INVALID || nupds == 0) /* not initialized yet */
		return 0; /* Ignore this update */

	swim_dump_updates(self_id, from, self_id, upds, nupds);

	swim_ctx_lock(ctx);
	ctx_state = swim_state_get(ctx);

	if (ctx_state == SCS_DPINGED && from == ctx->sc_target)
		ctx_state = SCS_ACKED;

	to = upds[0].smu_id; /* save first index from update */
	for (i = 0; i < nupds; i++) {
		switch (upds[i].smu_state.sms_status) {
		case SWIM_MEMBER_ALIVE:
			/* ignore alive updates for self */
			if (upds[i].smu_id == self_id)
				break;

			if (ctx_state == SCS_IPINGED &&
			    upds[i].smu_id == ctx->sc_target)
				ctx_state = SCS_ACKED;

			swim_member_alive(ctx, from, upds[i].smu_id,
					  upds[i].smu_state.sms_incarnation);
			break;
		case SWIM_MEMBER_SUSPECT:
			if (upds[i].smu_id == self_id) {
				/* increment our incarnation number if we are
				 * suspected in the current incarnation
				 */
				rc = ctx->sc_ops->get_member_state(ctx,
								upds[i].smu_id,
								&self_state);
				if (rc) {
					swim_ctx_unlock(ctx);
					SWIM_ERROR("get_member_state() failed "
						   "rc=%d\n", rc);
					D_GOTO(out, rc);
				}

				if (self_state.sms_incarnation >
				    upds[i].smu_state.sms_incarnation)
					break; /* already incremented */

				self_state.sms_incarnation++;
				SWIM_INFO("%lu: self SUSPECT received "
					  "(new incarnation=%lu)\n", self_id,
					  self_state.sms_incarnation);
				rc = swim_updates_notify(ctx, self_id, self_id,
							 &self_state);
				if (rc) {
					swim_ctx_unlock(ctx);
					SWIM_ERROR("swim_updates_notify() "
						   "failed rc=%d\n", rc);
					D_GOTO(out, rc);
				}
				break;
			}

			swim_member_suspect(ctx, from, upds[i].smu_id,
					    upds[i].smu_state.sms_incarnation);
			break;
		case SWIM_MEMBER_DEAD:
			/* if we get an update that we are dead,
			 * just shut down
			 */
			if (upds[i].smu_id == self_id) {
				swim_ctx_unlock(ctx);
				SWIM_INFO("%lu: self confirmed DEAD "
					  "(incarnation=%lu)\n", self_id,
					  upds[i].smu_state.sms_incarnation);
				D_GOTO(out, rc = -ESHUTDOWN);
			}

			swim_member_dead(ctx, from, upds[i].smu_id,
					 upds[i].smu_state.sms_incarnation);
			break;
		}
	}

	if (to == self_id) { /* dping request */
		/* send dping response */
		id_target = self_id;
		id_sendto = from;
		send_updates = true;
		SWIM_INFO("%lu: dresp %lu => %lu\n",
			  self_id, id_target, id_sendto);
	} else if (to == from) { /* dping response */
		/* forward this dping response to appropriate target */
		TAILQ_FOREACH(item, &ctx->sc_ipings, si_link) {
			if (item->si_id == from) {
				id_target = to;
				id_sendto = item->si_from;
				send_updates = true;
				SWIM_INFO("%lu: iresp %lu => %lu\n",
					  self_id, id_target, id_sendto);

				TAILQ_REMOVE(&ctx->sc_ipings, item,
					     si_link);
				D_FREE(item);
				break;
			}
		}
	} else { /* iping request or response */
		if (to != ctx->sc_target &&
		    upds[0].smu_state.sms_status == SWIM_MEMBER_SUSPECT) {
			/* send dping request to iping target */
			id_target = to;
			id_sendto = to;
			send_updates = true;

			/* looking if sent already */
			TAILQ_FOREACH(item, &ctx->sc_ipings, si_link) {
				if (item->si_id == to) {
					/* don't send a second time */
					send_updates = false;
					break;
				}
			}

			D_ALLOC_PTR(item);
			if (item != NULL) {
				item->si_id   = to;
				item->si_from = from;
				item->u.si_deadline = swim_now_ms()
						    + swim_ping_timeout;
				TAILQ_INSERT_TAIL(&ctx->sc_ipings, item,
						  si_link);
				SWIM_INFO("%lu: iping %lu => %lu\n",
					  self_id, from, to);
			} else {
				send_updates = false;
				rc = -ENOMEM;
			}
		}
	}

	swim_state_set(ctx, ctx_state);
	swim_ctx_unlock(ctx);

	while (send_updates) {
		rc = swim_updates_send(ctx, id_target, id_sendto);
		if (rc)
			SWIM_ERROR("swim_updates_send() failed rc=%d\n", rc);

		send_updates = false;
		if (to != self_id && to == from) { /* dping response */
			/* forward this dping response to appropriate target */
			swim_ctx_lock(ctx);
			TAILQ_FOREACH(item, &ctx->sc_ipings, si_link) {
				if (item->si_id == from) {
					id_target = to;
					id_sendto = item->si_from;
					send_updates = true;
					SWIM_INFO("%lu: iresp %lu => %lu\n",
						  self_id, id_target,
						  id_sendto);

					TAILQ_REMOVE(&ctx->sc_ipings, item,
						     si_link);
					D_FREE(item);
					break;
				}
			}
			swim_ctx_unlock(ctx);
		}
	}
out:
	return rc;
}
