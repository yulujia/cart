/* Copyright (C) 2016-2019 Intel Corporation
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
 *  4. All publications or advertising materials mentioning features or use of
 *     this software are asked, but not required, to acknowledge that it was
 *     developed by Intel Corporation and credit the contributors.
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
 *
 * This is a simple example of cart rpc group test based on crt API.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <getopt.h>
#include <semaphore.h>

#include <gurt/common.h>
#include <gurt/fault_inject.h>
#include <cart/api.h>
#include "crt_fake_events.h"
#include "test_group_rpc.h"

#define TEST_CTX_MAX_NUM	 (72)

#define TEST_GROUP_BASE          0x010000000
#define TEST_GROUP_VER           0


struct test_t {
	crt_group_t	*t_local_group;
	crt_group_t	*t_remote_group;
	char		*t_local_group_name;
	char		*t_remote_group_name;
	uint32_t	 t_remote_group_size;
	d_rank_t	 t_my_rank;
	uint32_t	 t_should_attach:1,
			 t_shutdown:1,
			 t_complete:1;
	int		 t_is_service;
	int		 t_infinite_loop;
	int		 t_hold;
	int		 t_shut_only;
	uint32_t	 t_hold_time;
	unsigned int	 t_ctx_num;
	crt_context_t	 t_crt_ctx[TEST_CTX_MAX_NUM];
	int		 t_thread_id[TEST_CTX_MAX_NUM]; /* logical tid */
	pthread_t	 t_tid[TEST_CTX_MAX_NUM];
	sem_t		 t_token_to_proceed;
	int		 t_roomno;
	struct d_fault_attr_t	 *t_fault_attr_1000;
	struct d_fault_attr_t	 *t_fault_attr_5000;
};

struct test_t test_g = { .t_hold_time = 0, .t_ctx_num = 1, .t_roomno = 1082 };

#define CRT_ISEQ_TEST_PING_CHECK /* input fields */		 \
	((uint32_t)		(age)			CRT_VAR) \
	((uint32_t)		(days)			CRT_VAR) \
	((d_string_t)		(name)			CRT_VAR) \
	((bool)			(bool_val)		CRT_VAR)

#define CRT_OSEQ_TEST_PING_CHECK /* output fields */		 \
	((int32_t)		(ret)			CRT_VAR) \
	((uint32_t)		(room_no)		CRT_VAR) \
	((uint32_t)		(bool_val)		CRT_VAR)

CRT_RPC_DECLARE(test_ping_check,
		CRT_ISEQ_TEST_PING_CHECK, CRT_OSEQ_TEST_PING_CHECK)
CRT_RPC_DEFINE(test_ping_check,
		CRT_ISEQ_TEST_PING_CHECK, CRT_OSEQ_TEST_PING_CHECK)

static inline void
test_sem_timedwait(sem_t *sem, int sec, int line_number)
{
	struct timespec			deadline;
	int				rc;

	rc = clock_gettime(CLOCK_REALTIME, &deadline);
	D_ASSERTF(rc == 0, "clock_gettime() failed at line %d rc: %d\n",
		  line_number, rc);
	deadline.tv_sec += sec;
	rc = sem_timedwait(sem, &deadline);
	D_ASSERTF(rc == 0, "sem_timedwait() failed at line %d rc: %d\n",
		  line_number, rc);
}

void
test_checkin_handler(crt_rpc_t *rpc_req)
{
	struct test_ping_check_in	*e_req;
	struct test_ping_check_out	*e_reply;
	int				 rc = 0;

	/* CaRT internally already allocated the input/output buffer */
	e_req = crt_req_get(rpc_req);
	D_ASSERTF(e_req != NULL, "crt_req_get() failed. e_req: %p\n", e_req);

	printf("tier1 test_server recv'd checkin, opc: %#x.\n",
	       rpc_req->cr_opc);
	printf("tier1 checkin input - age: %d, name: %s, days: %d, "
	       "bool_val %d.\n",
	       e_req->age, e_req->name, e_req->days, e_req->bool_val);

	e_reply = crt_reply_get(rpc_req);
	D_ASSERTF(e_reply != NULL, "crt_reply_get() failed. e_reply: %p\n",
		  e_reply);
	e_reply->ret = 0;
	e_reply->room_no = test_g.t_roomno++;
	e_reply->bool_val = e_req->bool_val;
	if (D_SHOULD_FAIL(test_g.t_fault_attr_5000)) {
		e_reply->ret = -DER_MISC;
		e_reply->room_no = -1;
	} else {
		D_DEBUG(DB_ALL, "No fault injected.\n");
	}

	rc = crt_reply_send(rpc_req);
	D_ASSERTF(rc == 0, "crt_reply_send() failed. rc: %d\n", rc);

	printf("tier1 test_srver sent checkin reply, ret: %d, room_no: %d.\n",
	       e_reply->ret, e_reply->room_no);
}

void
test_ping_delay_handler(crt_rpc_t *rpc_req)
{
	struct crt_test_ping_delay_in	*p_req;
	struct crt_test_ping_delay_out	*p_reply;
	int				 rc = 0;

	/* CaRT internally already allocated the input/output buffer */
	p_req = crt_req_get(rpc_req);
	D_ASSERTF(p_req != NULL, "crt_req_get() failed. p_req: %p\n", p_req);

	printf("tier1 test_server recv'd checkin, opc: %#x.\n",
	       rpc_req->cr_opc);
	printf("tier1 checkin input - age: %d, name: %s, days: %d, "
	       "delay: %u.\n",
	       p_req->age, p_req->name, p_req->days, p_req->delay);

	p_reply = crt_reply_get(rpc_req);
	D_ASSERTF(p_reply != NULL, "crt_reply_get() failed. p_reply: %p\n",
		  p_reply);
	p_reply->ret = 0;
	p_reply->room_no = test_g.t_roomno++;

	sleep(p_req->delay);

	rc = crt_reply_send(rpc_req);
	D_ASSERTF(rc == 0, "crt_reply_send() failed. rc: %d\n", rc);

	printf("tier1 test_srver sent checkin reply, ret: %d, room_no: %d.\n",
	       p_reply->ret, p_reply->room_no);
}

void
client_cb_common(const struct crt_cb_info *cb_info)
{
	crt_rpc_t			*rpc_req;
	struct test_ping_check_in	*rpc_req_input;
	struct test_ping_check_out	*rpc_req_output;

	rpc_req = cb_info->cci_rpc;

	if (cb_info->cci_arg != NULL)
		*(int *) cb_info->cci_arg = 1;

	switch (cb_info->cci_rpc->cr_opc) {
	case TEST_OPC_CHECKIN:
		rpc_req_input = crt_req_get(rpc_req);
		if (rpc_req_input == NULL)
			return;
		rpc_req_output = crt_reply_get(rpc_req);
		if (rpc_req_output == NULL)
			return;
		if (cb_info->cci_rc != 0) {
			D_ERROR("rpc (opc: %#x) failed, rc: %d.\n",
				rpc_req->cr_opc, cb_info->cci_rc);
			D_FREE(rpc_req_input->name);
			break;
		}
		printf("%s checkin result - ret: %d, room_no: %d, "
		       "bool_val %d.\n",
		       rpc_req_input->name, rpc_req_output->ret,
		       rpc_req_output->room_no, rpc_req_output->bool_val);
		D_FREE(rpc_req_input->name);
		sem_post(&test_g.t_token_to_proceed);
		D_ASSERT(rpc_req_output->bool_val == true);
		break;
	case TEST_OPC_SHUTDOWN:
		test_g.t_complete = 1;
		sem_post(&test_g.t_token_to_proceed);
		break;
	default:
		break;
	}
}

static void *progress_thread(void *arg)
{
	crt_context_t	ctx;
	pthread_t	current_thread = pthread_self();
	int		num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_set_t	cpuset;
	int		t_idx;
	int		rc;

	t_idx = *(int *)arg;
	CPU_ZERO(&cpuset);
	CPU_SET(t_idx % num_cores, &cpuset);
	pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);

	fprintf(stderr, "progress thread %d running on core %d...\n",
		t_idx, sched_getcpu());

	ctx = (crt_context_t)test_g.t_crt_ctx[t_idx];
	/* progress loop */
	do {
		rc = crt_progress(ctx, 0, NULL, NULL);
		if (rc != 0 && rc != -DER_TIMEDOUT) {
			D_ERROR("crt_progress failed rc: %d.\n", rc);
		}
		if (test_g.t_shutdown == 1 && test_g.t_complete == 1)
			break;
	} while (!dead);

	printf("progress_thread: rc: %d, test_srv.do_shutdown: %d.\n",
	       rc, test_g.t_shutdown);
	printf("progress_thread: progress thread exit ...\n");

	pthread_exit(NULL);
}

void test_shutdown_handler(crt_rpc_t *rpc_req)
{
	printf("tier1 test_srver received shutdown request, opc: %#x.\n",
	       rpc_req->cr_opc);

	D_ASSERTF(rpc_req->cr_input == NULL, "RPC request has invalid input\n");
	D_ASSERTF(rpc_req->cr_output == NULL, "RPC request output is NULL\n");

	test_g.t_shutdown = 1;
	printf("tier1 test_srver set shutdown flag.\n");
}

static struct crt_proto_rpc_format my_proto_rpc_fmt_test_group1[] = {
	{
		.prf_flags	= 0,
		.prf_req_fmt	= &CQF_test_ping_check,
		.prf_hdlr	= test_checkin_handler,
		.prf_co_ops	= NULL,
	}, {
		.prf_flags	= CRT_RPC_FEAT_NO_REPLY,
		.prf_req_fmt	= NULL,
		.prf_hdlr	= test_shutdown_handler,
		.prf_co_ops	= NULL,
	}, {
		.prf_flags	= CRT_RPC_FEAT_NO_TIMEOUT,
		.prf_req_fmt	= &CQF_crt_test_ping_delay,
		.prf_hdlr	= test_ping_delay_handler,
		.prf_co_ops	= NULL,
	}
};

static struct crt_proto_format my_proto_fmt_test_group1 = {
	.cpf_name = "my-proto-test-group1",
	.cpf_ver = TEST_GROUP_VER,
	.cpf_count = ARRAY_SIZE(my_proto_rpc_fmt_test_group1),
	.cpf_prf = &my_proto_rpc_fmt_test_group1[0],
	.cpf_base = TEST_GROUP_BASE,
};

static struct crt_proto_rpc_format my_proto_rpc_fmt_test_group2[] = {
	{
		.prf_flags	= 0,
		.prf_req_fmt	= &CQF_test_ping_check,
		.prf_hdlr	= test_checkin_handler,
		.prf_co_ops	= NULL,
	}, {
		.prf_flags	= CRT_RPC_FEAT_NO_REPLY,
		.prf_req_fmt	= NULL,
		.prf_hdlr	= test_shutdown_handler,
		.prf_co_ops	= NULL,
	}
};

static struct crt_proto_format my_proto_fmt_test_group2 = {
	.cpf_name = "my-proto-test-group2",
	.cpf_ver = TEST_GROUP_VER,
	.cpf_count = ARRAY_SIZE(my_proto_rpc_fmt_test_group2),
	.cpf_prf = &my_proto_rpc_fmt_test_group2[0],
	.cpf_base = TEST_GROUP_BASE,
};

void
test_init(void)
{
	uint32_t	flag;
	int		i;
	int		rc = 0;

	fprintf(stderr, "local group: %s remote group: %s\n",
		test_g.t_local_group_name, test_g.t_remote_group_name);

	/* In order to use things like D_ASSERTF, logging needs to be active
	 * even if cart is not
	 */
	rc = d_log_init();
	D_ASSERT(rc == 0);

	rc = sem_init(&test_g.t_token_to_proceed, 0, 0);
	D_ASSERTF(rc == 0, "sem_init() failed.\n");

	flag = test_g.t_is_service ? CRT_FLAG_BIT_SERVER : 0;
	if (test_g.t_shut_only)
		flag |= CRT_FLAG_BIT_SINGLETON;
	rc = crt_init(test_g.t_local_group_name, flag);
	D_ASSERTF(rc == 0, "crt_init() failed, rc: %d\n", rc);

	test_g.t_fault_attr_1000 = d_fault_attr_lookup(1000);
	test_g.t_fault_attr_5000 = d_fault_attr_lookup(5000);

	rc = crt_group_rank(NULL, &test_g.t_my_rank);
	D_ASSERTF(rc == 0, "crt_group_rank() failed. rc: %d\n", rc);
	if (test_g.t_is_service) {
		rc = crt_group_config_save(NULL, true);
		D_ASSERTF(rc == 0, "crt_group_config_save() failed. rc: %d\n",
			rc);
		crt_fake_event_init(test_g.t_my_rank);
		D_ASSERTF(rc == 0, "crt_fake_event_init() failed. rc: %d\n",
			  rc);
	}

	/* register RPCs */
	if (test_g.t_is_service) {
		rc = crt_proto_register(&my_proto_fmt_test_group1);
		D_ASSERTF(rc == 0, "crt_proto_register() failed. rc: %d\n",
			rc);
	} else {
		rc = crt_proto_register(&my_proto_fmt_test_group2);
		D_ASSERTF(rc == 0, "crt_proto_register() failed. rc: %d\n",
			rc);
	}

	for (i = 0; i < test_g.t_ctx_num; i++) {
		test_g.t_thread_id[i] = i;
		rc = crt_context_create(&test_g.t_crt_ctx[i]);
		D_ASSERTF(rc == 0, "crt_context_create() failed. rc: %d\n", rc);
		rc = pthread_create(&test_g.t_tid[i], NULL, progress_thread,
				    &test_g.t_thread_id[i]);
		D_ASSERTF(rc == 0, "pthread_create() failed. rc: %d\n", rc);
	}
	test_g.t_complete = 1;
}

void
check_in(crt_group_t *remote_group, int rank)
{
	crt_rpc_t			*rpc_req = NULL;
	struct test_ping_check_in	*rpc_req_input;
	crt_endpoint_t			 server_ep = {0};
	char				*buffer;
	int				 rc;

	server_ep.ep_grp = remote_group;
	server_ep.ep_rank = rank;
	rc = crt_req_create(test_g.t_crt_ctx[0], &server_ep,
			TEST_OPC_CHECKIN, &rpc_req);
	D_ASSERTF(rc == 0 && rpc_req != NULL, "crt_req_create() failed,"
			" rc: %d rpc_req: %p\n", rc, rpc_req);

	rpc_req_input = crt_req_get(rpc_req);
	D_ASSERTF(rpc_req_input != NULL, "crt_req_get() failed."
			" rpc_req_input: %p\n", rpc_req_input);

	/**
	 * example to inject faults to D_ALLOC. To turn it on, edit the fault
	 * config file: under fault id 1000, change the probability from 0 to
	 * anything in [1, 100]
	 */
	if (D_SHOULD_FAIL(test_g.t_fault_attr_1000)) {
		buffer = NULL;
	} else {
		D_ALLOC(buffer, 256);
		D_INFO("not injecting fault.\n");
	}

	D_ASSERTF(buffer != NULL, "Cannot allocate memory.\n");
	snprintf(buffer,  256, "Guest %d", test_g.t_my_rank);
	rpc_req_input->name = buffer;
	rpc_req_input->age = 21;
	rpc_req_input->days = 7;
	rpc_req_input->bool_val = true;
	D_DEBUG(DB_TEST, "client(rank %d) sending checkin rpc with tag "
		"%d, name: %s, age: %d, days: %d, bool_val %d.\n",
		test_g.t_my_rank, server_ep.ep_tag, rpc_req_input->name,
		rpc_req_input->age, rpc_req_input->days,
		rpc_req_input->bool_val);

	/* send an rpc, print out reply */
	rc = crt_req_send(rpc_req, client_cb_common, NULL);
	D_ASSERTF(rc == 0, "crt_req_send() failed. rc: %d\n", rc);
}

void
test_run(void)
{
	crt_group_t			*remote_group = NULL;
	int				 ii;
	int				 rc;

	if (!test_g.t_should_attach)
		return;

	if (test_g.t_is_service) {
		rc = crt_init(test_g.t_local_group_name, 0);
		D_ASSERTF(rc == 0, "crt_init() failed. rc: %d\n", rc);
	}

	/* try until success to avoid intermittent failures under valgrind. */
	do {
		sleep(1);
		rc = crt_group_attach(test_g.t_remote_group_name,
				      &test_g.t_remote_group);
	} while (rc != 0);
	D_ASSERTF(rc == 0, "crt_group_attach failed, rc: %d\n", rc);
	D_ASSERTF(test_g.t_remote_group != NULL, "NULL attached srv_grp\n");

	test_g.t_complete = 0;
	remote_group = crt_group_lookup(test_g.t_remote_group_name);
	D_ASSERTF(remote_group != NULL, "crt_group_lookup() failed. "
		  "remote_group = %p\n", remote_group);
	crt_group_size(remote_group, &test_g.t_remote_group_size);
	fprintf(stderr, "size of %s is %d\n", test_g.t_remote_group_name,
		test_g.t_remote_group_size);

	/* send shutdown to the target group, don't run any test */
	if (test_g.t_shut_only)
		return;
	for (ii = 0; ii < test_g.t_remote_group_size; ii++)
		check_in(test_g.t_remote_group, ii);

	for (ii = 0; ii < test_g.t_remote_group_size; ii++)
		test_sem_timedwait(&test_g.t_token_to_proceed, 61, __LINE__);

	while (test_g.t_infinite_loop) {
		check_in(test_g.t_remote_group, 1);
		test_sem_timedwait(&test_g.t_token_to_proceed, 61, __LINE__);
	}
}

void
test_fini()
{
	int				 ii;
	crt_endpoint_t			 server_ep = {0};
	crt_rpc_t			*rpc_req = NULL;
	int				 rc = 0;

	if (test_g.t_should_attach && test_g.t_my_rank == 0) {
		/* client rank 0 tells all servers to shut down */
		for (ii = 0; ii < test_g.t_remote_group_size; ii++) {
			server_ep.ep_grp = test_g.t_remote_group;
			server_ep.ep_rank = ii;
			rc = crt_req_create(test_g.t_crt_ctx[0], &server_ep,
				CRT_PROTO_OPC(TEST_GROUP_BASE,
				TEST_GROUP_VER, 1), &rpc_req);
			D_ASSERTF(rc == 0 && rpc_req != NULL,
				  "crt_req_create() failed. "
				  "rc: %d, rpc_req: %p\n", rc, rpc_req);
			rc = crt_req_send(rpc_req, client_cb_common, NULL);
			D_ASSERTF(rc == 0, "crt_req_send() failed. rc: %d\n",
				  rc);

			test_sem_timedwait(&test_g.t_token_to_proceed, 61,
					   __LINE__);
		}
	}
	if (test_g.t_should_attach) {
		rc = crt_group_detach(test_g.t_remote_group);
		D_ASSERTF(rc == 0, "crt_group_detach failed, rc: %d\n", rc);
	}
	if (!test_g.t_is_service)
		test_g.t_shutdown = 1;

	for (ii = 0; ii < test_g.t_ctx_num; ii++) {
		rc = pthread_join(test_g.t_tid[ii], NULL);
		if (rc != 0)
			fprintf(stderr, "pthread_join failed. rc: %d\n", rc);
		D_DEBUG(DB_TEST, "joined progress thread.\n");

		/* try to flush indefinitely */
		rc = crt_context_flush(test_g.t_crt_ctx[ii], 0);
		D_ASSERTF(rc == 0 || rc == -DER_TIMEDOUT,
			  "crt_context_flush() failed. rc: %d\n", rc);

		rc = crt_context_destroy(test_g.t_crt_ctx[ii], 0);
		D_ASSERTF(rc == 0, "crt_context_destroy() failed. rc: %d\n",
			  rc);
		D_DEBUG(DB_TEST, "destroyed crt_ctx.\n");
	}

	if (test_g.t_is_service)
		crt_fake_event_fini(test_g.t_my_rank);
	rc = sem_destroy(&test_g.t_token_to_proceed);
	D_ASSERTF(rc == 0, "sem_destroy() failed.\n");
	/* corresponding to the crt_init() in run_test_group() */
	if (test_g.t_should_attach && test_g.t_is_service) {
		rc = crt_finalize();
		D_ASSERTF(rc == 0, "crt_finalize() failed. rc: %d\n", rc);
	}
	if (test_g.t_is_service && test_g.t_my_rank == 0) {
		rc = crt_group_config_remove(NULL);
		assert(rc == 0);
	}

	rc = crt_finalize();
	D_ASSERTF(rc == 0, "crt_finalize() failed. rc: %d\n", rc);

	d_log_fini();

	D_DEBUG(DB_TEST, "exiting.\n");
}

int
test_parse_args(int argc, char **argv)
{
	int				option_index = 0;
	int				rc = 0;
	struct option			long_options[] = {
		{"name", required_argument, 0, 'n'},
		{"attach_to", required_argument, 0, 'a'},
		{"holdtime", required_argument, 0, 'h'},
		{"hold", no_argument, &test_g.t_hold, 1},
		{"is_service", no_argument, &test_g.t_is_service, 1},
		{"ctx_num", required_argument, 0, 'c'},
		{"loop", no_argument, &test_g.t_infinite_loop, 1},
		{"shut_only", no_argument, &test_g.t_shut_only, 1},
		{0, 0, 0, 0}
	};

	while (1) {
		rc = getopt_long(argc, argv, "n:a:c:h:", long_options,
				 &option_index);
		if (rc == -1)
			break;
		switch (rc) {
		case 0:
			if (long_options[option_index].flag != 0)
				break;
		case 'n':
			test_g.t_local_group_name = optarg;
			break;
		case 'a':
			test_g.t_remote_group_name = optarg;
			test_g.t_should_attach = 1;
			break;
		case 'c': {
			unsigned int	nr;
			char		*end;

			nr = strtoul(optarg, &end, 10);
			if (end == optarg || nr == 0 || nr > TEST_CTX_MAX_NUM) {
				fprintf(stderr, "invalid ctx_num %d exceed "
					"[%d, %d], using 1 for test.\n", nr,
					1, TEST_CTX_MAX_NUM);
			} else {
				test_g.t_ctx_num = nr;
				fprintf(stderr, "will create %d contexts.\n",
					nr);
			}
			break;
		}
		case 'h':
			test_g.t_hold = 1;
			test_g.t_hold_time = atoi(optarg);
			break;
		case '?':
			return 1;
		default:
			return 1;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "non-option argv elements encountered");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int	rc;

	rc = test_parse_args(argc, argv);
	if (rc != 0) {
		fprintf(stderr, "test_parse_args() failed, rc: %d.\n",
			rc);
		return rc;
	}

	test_init();
	test_run();
	if (test_g.t_hold)
		sleep(test_g.t_hold_time);
	test_fini();

	return rc;
}
