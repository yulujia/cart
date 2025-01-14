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
 */
/**
 * This file is part of CaRT. It implements CaRT init and finalize related
 * APIs/handling.
 */

#include "crt_internal.h"

struct crt_gdata crt_gdata;
static volatile int   gdata_init_flag;
struct crt_plugin_gdata crt_plugin_gdata;

/* first step init - for initializing crt_gdata */
static int data_init(crt_init_options_t *opt)
{
	uint32_t	timeout;
	uint32_t	credits;
	bool		share_addr = false;
	uint32_t	ctx_num = 1;
	int		rc = 0;

	D_DEBUG(DB_ALL, "initializing crt_gdata...\n");

	/*
	 * avoid size mis-matching between client/server side
	 * /see crt_proc_uuid_t().
	 */
	D_CASSERT(sizeof(uuid_t) == 16);

	D_INIT_LIST_HEAD(&crt_gdata.cg_ctx_list);

	rc = D_RWLOCK_INIT(&crt_gdata.cg_rwlock, NULL);
	if (rc != 0) {
		D_ERROR("Failed to init cg_rwlock\n");
		D_GOTO(exit, rc);
	}

	crt_gdata.cg_ctx_num = 0;
	crt_gdata.cg_refcount = 0;
	crt_gdata.cg_inited = 0;
	crt_gdata.cg_addr = NULL;
	crt_gdata.cg_na_plugin = CRT_NA_OFI_SOCKETS;
	crt_gdata.cg_share_na = false;

	timeout = 0;

	if (opt && opt->cio_crt_timeout != 0)
		timeout = opt->cio_crt_timeout;
	else
		d_getenv_int("CRT_TIMEOUT", &timeout);

	if (timeout == 0 || timeout > 3600)
		crt_gdata.cg_timeout = CRT_DEFAULT_TIMEOUT_S;
	else
		crt_gdata.cg_timeout = timeout;

	D_DEBUG(DB_ALL, "set the global timeout value as %d second.\n",
		crt_gdata.cg_timeout);

	/* Override defaults and environment if option is set */
	if (opt && opt->cio_use_credits) {
		credits = opt->cio_ep_credits;
	} else {
		credits = CRT_DEFAULT_CREDITS_PER_EP_CTX;
		d_getenv_int("CRT_CREDIT_EP_CTX", &credits);
	}

	if (credits == 0) {
		D_DEBUG(DB_ALL, "CRT_CREDIT_EP_CTX set as 0, flow control "
			"disabled.\n");
	} else if (credits > CRT_MAX_CREDITS_PER_EP_CTX) {
		D_DEBUG(DB_ALL, "ENV CRT_CREDIT_EP_CTX's value %d exceed max "
			"allowed value, use %d for flow control.\n",
			credits, CRT_MAX_CREDITS_PER_EP_CTX);
		credits = CRT_MAX_CREDITS_PER_EP_CTX;
	} else {
		D_DEBUG(DB_ALL, "CRT_CREDIT_EP_CTX set as %d for flow "
			"control.\n", credits);
	}
	crt_gdata.cg_credit_ep_ctx = credits;
	D_ASSERT(crt_gdata.cg_credit_ep_ctx <= CRT_MAX_CREDITS_PER_EP_CTX);

	if (opt && opt->cio_sep_override) {
		if (opt->cio_use_sep) {
			crt_gdata.cg_share_na = true;
			D_DEBUG(DB_ALL, "crt_gdata.cg_share_na turned on.\n");
		}
		crt_gdata.cg_ctx_max_num = opt->cio_ctx_max_num;
	} else {
		d_getenv_bool("CRT_CTX_SHARE_ADDR", &share_addr);
		if (share_addr) {
			crt_gdata.cg_share_na = true;
			D_DEBUG(DB_ALL, "crt_gdata.cg_share_na turned on.\n");
		}

		d_getenv_int("CRT_CTX_NUM", &ctx_num);
		crt_gdata.cg_ctx_max_num = ctx_num;
	}
	D_DEBUG(DB_ALL, "set cg_share_na %d, cg_ctx_max_num %d.\n",
		crt_gdata.cg_share_na, crt_gdata.cg_ctx_max_num);
	if (crt_gdata.cg_share_na == false && crt_gdata.cg_ctx_max_num > 1)
		D_WARN("CRT_CTX_NUM has no effect because CRT_CTX_SHARE_ADDR "
		       "is not set or set to 0\n");

	if (opt) {
		if (opt->cio_fault_inject)
			d_fault_inject_enable();
		else
			d_fault_inject_disable();
	}

	gdata_init_flag = 1;
exit:
	return rc;
}

static int
crt_plugin_init(void)
{
	int i, rc;

	D_ASSERT(crt_plugin_gdata.cpg_inited == 0);

	/** init the lists */
	for (i = 0; i < CRT_SRV_CONTEXT_NUM; i++) {
		D_INIT_LIST_HEAD(&crt_plugin_gdata.cpg_prog_cbs[i]);
		rc = D_RWLOCK_INIT(&crt_plugin_gdata.cpg_prog_rwlock[i], NULL);
		if (rc != 0)
			D_GOTO(out, rc);
	}

	D_INIT_LIST_HEAD(&crt_plugin_gdata.cpg_timeout_cbs);
	rc = D_RWLOCK_INIT(&crt_plugin_gdata.cpg_timeout_rwlock, NULL);
	if (rc != 0)
		D_GOTO(out_destroy_prog, rc);

	D_INIT_LIST_HEAD(&crt_plugin_gdata.cpg_event_cbs);
	rc = D_RWLOCK_INIT(&crt_plugin_gdata.cpg_event_rwlock, NULL);
	if (rc != 0)
		D_GOTO(out_destroy_timeout, rc);

	D_INIT_LIST_HEAD(&crt_plugin_gdata.cpg_eviction_cbs);
	rc = D_RWLOCK_INIT(&crt_plugin_gdata.cpg_eviction_rwlock, NULL);
	if (rc != 0)
		D_GOTO(out_destroy_event, rc);

	crt_plugin_gdata.cpg_inited = 1;
	if (CRT_PMIX_ENABLED() && crt_is_service() && !crt_is_singleton()) {
		rc = crt_plugin_pmix_init();
		if (rc != 0)
			D_GOTO(out_destroy_eviction, rc);
	}
	D_GOTO(out, rc = 0);

out_destroy_eviction:
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_eviction_rwlock);
out_destroy_event:
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_event_rwlock);
out_destroy_timeout:
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_timeout_rwlock);
out_destroy_prog:
	for (i = 0; i < CRT_SRV_CONTEXT_NUM; i++)
		D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_prog_rwlock[i]);
out:
	return rc;
}

int
crt_init_opt(crt_group_id_t grpid, uint32_t flags, crt_init_options_t *opt)
{
	crt_phy_addr_t	addr = NULL, addr_env;
	struct timeval	now;
	unsigned int	seed;
	const char	*path;
	bool		server;
	bool		provider_found = false;
	int		plugin_idx;
	int		rc = 0;

	server = flags & CRT_FLAG_BIT_SERVER;

	/* d_log_init is reference counted */
	rc = d_log_init();
	if (rc != 0) {
		D_PRINT_ERR("d_log_init failed, rc: %d.\n", rc);
		return rc;
	}

	crt_setup_log_fac();

	/* d_fault_inject_init() is reference counted */
	rc = d_fault_inject_init();
	if (rc != DER_SUCCESS) {
		D_ERROR("d_fault_inject_init() failed, rc: %d.\n", rc);
		D_GOTO(out, rc);
	}

	if (grpid != NULL) {
		if (crt_validate_grpid(grpid) != 0) {
			D_ERROR("grpid contains invalid characters "
				"or is too long\n");
			D_GOTO(out, rc = -DER_INVAL);
		}
		if (!server) {
			if (strcmp(grpid, CRT_DEFAULT_SRV_GRPID) == 0) {
				D_ERROR("invalid client grpid (same as "
					"CRT_DEFAULT_SRV_GRPID).\n");
				D_GOTO(out, rc = -DER_INVAL);
			}
		} else {
			if (strcmp(grpid, CRT_DEFAULT_CLI_GRPID) == 0) {
				D_ERROR("invalid server grpid (same as "
					"CRT_DEFAULT_CLI_GRPID).\n");
				D_GOTO(out, rc = -DER_INVAL);
			}
		}
	}

	if (gdata_init_flag == 0) {
		rc = data_init(opt);
		if (rc != 0) {
			D_ERROR("data_init failed, rc(%d) - %s.\n",
				rc, strerror(rc));
			D_GOTO(out, rc = -rc);
		}
	}
	D_ASSERT(gdata_init_flag == 1);

	if ((flags & CRT_FLAG_BIT_PMIX_DISABLE) != 0) {
		crt_gdata.cg_pmix_disabled = 1;

		/* Liveness map only valid with PMIX enabled */
		if (!(flags & CRT_FLAG_BIT_LM_DISABLE)) {
			D_WARN("PMIX disabled. Disabling LM automatically\n");
			flags |= CRT_FLAG_BIT_LM_DISABLE;
		}
	}

	D_RWLOCK_WRLOCK(&crt_gdata.cg_rwlock);
	if (crt_gdata.cg_inited == 0) {
		/* feed a seed for pseudo-random number generator */
		gettimeofday(&now, NULL);
		seed = (unsigned int)(now.tv_sec * 1000000 + now.tv_usec);
		srandom(seed);

		crt_gdata.cg_server = server;

		if ((flags & CRT_FLAG_BIT_SINGLETON) != 0)
			crt_gdata.cg_singleton = true;

		path = getenv("CRT_ATTACH_INFO_PATH");
		if (path != NULL && strlen(path) > 0) {
			rc = crt_group_config_path_set(path);
			if (rc != 0)
				D_ERROR("Got %s from ENV CRT_ATTACH_INFO_PATH, "
					"but crt_group_config_path_set failed "
					"rc: %d, ignore the ENV.\n", path, rc);
			else
				D_DEBUG(DB_ALL, "set group_config_path as "
					"%s.\n", path);
		}

		addr_env = (crt_phy_addr_t)getenv(CRT_PHY_ADDR_ENV);
		if (addr_env == NULL) {
			D_DEBUG(DB_ALL, "ENV %s not found.\n",
				CRT_PHY_ADDR_ENV);
			goto do_init;
		} else{
			D_DEBUG(DB_ALL, "EVN %s: %s.\n", CRT_PHY_ADDR_ENV,
				addr_env);
		}

		provider_found = false;
		for (plugin_idx = 0; crt_na_dict[plugin_idx].nad_str != NULL;
		     plugin_idx++) {
			if (!strncmp(addr_env, crt_na_dict[plugin_idx].nad_str,
				strlen(crt_na_dict[plugin_idx].nad_str) + 1)) {
				crt_gdata.cg_na_plugin =
					crt_na_dict[plugin_idx].nad_type;
				provider_found = true;
				break;
			}
		}

		if (!provider_found) {
			D_ERROR("Requested provider %s not found\n", addr_env);
			D_GOTO(out, rc = -DER_NONEXIST);
		}
do_init:
		/* the verbs provider only works with regular EP */
		if ((crt_gdata.cg_na_plugin == CRT_NA_OFI_VERBS_RXM ||
		     crt_gdata.cg_na_plugin == CRT_NA_OFI_VERBS) &&
		    crt_gdata.cg_share_na) {
			D_WARN("set CRT_CTX_SHARE_ADDR as 1 is invalid "
			       "for verbs provider, ignore it.\n");
			crt_gdata.cg_share_na = false;
		}
		if (crt_na_type_is_ofi(crt_gdata.cg_na_plugin)) {
			rc = crt_na_ofi_config_init();
			if (rc != 0) {
				D_ERROR("crt_na_ofi_config_init failed, "
					"rc: %d.\n", rc);
				D_GOTO(out, rc);
			}
		}

		rc = crt_hg_init(&addr, server);
		if (rc != 0) {
			D_ERROR("crt_hg_init failed rc: %d.\n", rc);
			D_GOTO(cleanup, rc);
		}
		D_ASSERT(addr != NULL);
		crt_gdata.cg_addr = addr;

		rc = crt_grp_init(grpid);
		if (rc != 0) {
			D_ERROR("crt_grp_init failed, rc: %d.\n", rc);
			D_GOTO(cleanup, rc);
		}

		if (crt_plugin_gdata.cpg_inited == 0) {
			rc = crt_plugin_init();
			if (rc != 0) {
				D_ERROR("crt_plugin_init rc: %d.\n", rc);
				D_GOTO(cleanup, rc);
			}
		}

		crt_self_test_init();

		rc = crt_opc_map_create(CRT_OPC_MAP_BITS);
		if (rc != 0) {
			D_ERROR("crt_opc_map_create failed rc: %d.\n", rc);
			D_GOTO(cleanup, rc);
		}
		D_ASSERT(crt_gdata.cg_opc_map != NULL);

		crt_gdata.cg_inited = 1;
		if ((flags & CRT_FLAG_BIT_LM_DISABLE) == 0) {
			rc = crt_lm_init();
			if (rc)
				D_GOTO(cleanup, rc);
		}

		if (crt_is_service()) {
			rc = crt_swim_init(CRT_DEFAULT_PROGRESS_CTX_IDX);
			if (rc) {
				D_ERROR("crt_swim_init() failed rc: %d.\n", rc);
				crt_lm_finalize();
				D_GOTO(cleanup, rc);
			}
		}
	} else {
		if (crt_gdata.cg_server == false && server == true) {
			D_ERROR("CRT initialized as client, cannot set as "
				"server again.\n");
			D_GOTO(unlock, rc = -DER_INVAL);
		}
	}

	crt_gdata.cg_refcount++;

	D_GOTO(unlock, rc);

cleanup:
	crt_gdata.cg_inited = 0;
	if (crt_gdata.cg_addr != NULL) {
		crt_hg_fini();
		D_FREE(crt_gdata.cg_addr);
	}
	if (crt_gdata.cg_grp_inited == 1)
		crt_grp_fini();
	if (crt_gdata.cg_opc_map != NULL)
		crt_opc_map_destroy(crt_gdata.cg_opc_map);

	crt_na_ofi_config_fini();

unlock:
	D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);

out:
	if (rc != 0) {
		D_ERROR("crt_init failed, rc: %d.\n", rc);
		d_fault_inject_fini();
		d_log_fini();
	}
	return rc;
}

bool
crt_initialized()
{
	return (gdata_init_flag == 1) && (crt_gdata.cg_inited == 1);
}

void
crt_plugin_fini(void)
{
	struct crt_prog_cb_priv		*prog_cb_priv;
	struct crt_timeout_cb_priv	*timeout_cb_priv;
	struct crt_event_cb_priv	*event_cb_priv;
	struct crt_plugin_cb_priv	*cb_priv;
	int				 i;

	D_ASSERT(crt_plugin_gdata.cpg_inited == 1);

	if (CRT_PMIX_ENABLED())
		crt_plugin_pmix_fini();

	for (i = 0; i < CRT_SRV_CONTEXT_NUM; i++) {
		while ((prog_cb_priv = d_list_pop_entry(
					&crt_plugin_gdata.cpg_prog_cbs[i],
					struct crt_prog_cb_priv,
					cpcp_link))) {
			D_FREE(prog_cb_priv);
		}
	}

	while ((timeout_cb_priv = d_list_pop_entry(&crt_plugin_gdata.cpg_timeout_cbs,
						   struct crt_timeout_cb_priv,
						   ctcp_link))) {
		D_FREE(timeout_cb_priv);
	}
	while ((event_cb_priv = d_list_pop_entry(&crt_plugin_gdata.cpg_event_cbs,
						 struct crt_event_cb_priv,
						 cecp_link))) {
		D_FREE(event_cb_priv);
	}
	while ((cb_priv = d_list_pop_entry(&crt_plugin_gdata.cpg_eviction_cbs,
					   struct crt_plugin_cb_priv,
					   cp_link))) {
		D_FREE(cb_priv);
	}

	for (i = 0; i < CRT_SRV_CONTEXT_NUM; i++)
		D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_prog_rwlock[i]);
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_timeout_rwlock);
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_event_rwlock);
	D_RWLOCK_DESTROY(&crt_plugin_gdata.cpg_eviction_rwlock);
}

int
crt_finalize(void)
{
	int local_rc;
	int rc = 0;

	D_RWLOCK_WRLOCK(&crt_gdata.cg_rwlock);

	if (!crt_initialized()) {
		D_ERROR("cannot finalize before initializing.\n");
		D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
		D_GOTO(direct_out, rc = -DER_UNINIT);
	}
	crt_lm_finalize();

	crt_gdata.cg_refcount--;
	if (crt_gdata.cg_refcount == 0) {
		if (crt_gdata.cg_ctx_num > 0) {
			D_ASSERT(!crt_context_empty(CRT_LOCKED));
			D_ERROR("cannot finalize, current ctx_num(%d).\n",
				crt_gdata.cg_ctx_num);
			crt_gdata.cg_refcount++;
			D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
			D_GOTO(out, rc = -DER_NO_PERM);
		} else {
			D_ASSERT(crt_context_empty(CRT_LOCKED));
		}

		if (crt_plugin_gdata.cpg_inited == 1)
			crt_plugin_fini();

		if (crt_is_service())
			crt_swim_fini();

		rc = crt_grp_fini();
		if (rc != 0) {
			D_ERROR("crt_grp_fini failed, rc: %d.\n", rc);
			crt_gdata.cg_refcount++;
			D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
			D_GOTO(out, rc);
		}

		rc = crt_hg_fini();
		if (rc != 0) {
			D_ERROR("crt_hg_fini failed rc: %d.\n", rc);
			crt_gdata.cg_refcount++;
			D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
			D_GOTO(out, rc);
		}

		D_ASSERT(crt_gdata.cg_addr != NULL);
		D_FREE(crt_gdata.cg_addr);
		crt_gdata.cg_server = false;

		crt_opc_map_destroy(crt_gdata.cg_opc_map);

		D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
		rc = D_RWLOCK_DESTROY(&crt_gdata.cg_rwlock);
		if (rc != 0) {
			D_ERROR("failed to destroy cg_rwlock, rc: %d.\n", rc);
			D_GOTO(out, rc);
		}

		/* allow the same program to re-initialize */
		crt_gdata.cg_refcount = 0;
		crt_gdata.cg_inited = 0;
		gdata_init_flag = 0;

		if (crt_gdata.cg_na_plugin == CRT_NA_OFI_SOCKETS)
			crt_na_ofi_config_fini();
	} else {
		D_RWLOCK_UNLOCK(&crt_gdata.cg_rwlock);
	}

out:
	/* d_fault_inject_fini() is reference counted */
	local_rc = d_fault_inject_fini();
	if (local_rc != 0)
		D_ERROR("d_fault_inject_fini() failed, rc: %d\n", local_rc);

direct_out:
	if (rc == 0)
		d_log_fini(); /* d_log_fini is reference counted */
	else
		D_ERROR("crt_finalize failed, rc: %d.\n", rc);

	return rc;
}

/* global NA OFI plugin configuration */
struct na_ofi_config crt_na_ofi_conf;

static inline na_bool_t is_integer_str(char *str)
{
	char *p;

	p = str;
	if (p == NULL || strlen(p) == 0)
		return NA_FALSE;

	while (*p != '\0') {
		if (*p <= '9' && *p >= '0') {
			p++;
			continue;
		} else {
			return NA_FALSE;
		}
	}

	return NA_TRUE;
}

static inline int
crt_get_port(int *port)
{
	int			socketfd;
	struct sockaddr_in	tmp_socket;
	socklen_t		slen = sizeof(struct sockaddr);
	int			rc;

	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) {
		D_ERROR("cannot create socket, errno: %d(%s).\n",
			errno, strerror(errno));
		D_GOTO(out, rc = -DER_ADDRSTR_GEN);
	}
	tmp_socket.sin_family = AF_INET;
	tmp_socket.sin_addr.s_addr = INADDR_ANY;
	tmp_socket.sin_port = 0;

	rc = bind(socketfd, (const struct sockaddr *)&tmp_socket,
		  sizeof(tmp_socket));
	if (rc != 0) {
		D_ERROR("cannot bind socket, errno: %d(%s).\n",
			errno, strerror(errno));
		close(socketfd);
		D_GOTO(out, rc = -DER_ADDRSTR_GEN);
	}

	rc = getsockname(socketfd, (struct sockaddr *)&tmp_socket, &slen);
	if (rc != 0) {
		D_ERROR("cannot create getsockname, errno: %d(%s).\n",
			errno, strerror(errno));
		close(socketfd);
		D_GOTO(out, rc = -DER_ADDRSTR_GEN);
	}
	rc = close(socketfd);
	if (rc != 0) {
		D_ERROR("cannot close socket, errno: %d(%s).\n",
			errno, strerror(errno));
		D_GOTO(out, rc = -DER_ADDRSTR_GEN);
	}

	D_ASSERT(port != NULL);
	*port = ntohs(tmp_socket.sin_port);
	D_DEBUG(DB_ALL, "get a port: %d.\n", *port);

out:
	return rc;
}

int crt_na_ofi_config_init(void)
{
	char		*port_str;
	char		*interface;
	int		port;
	struct ifaddrs	*if_addrs = NULL;
	struct ifaddrs	*ifa = NULL;
	void		*tmp_ptr;
	const char	*ip_str = NULL;
	int		rc = 0;

	interface = getenv("OFI_INTERFACE");
	if (interface != NULL && strlen(interface) > 0) {
		D_STRNDUP(crt_na_ofi_conf.noc_interface, interface, 64);
		if (crt_na_ofi_conf.noc_interface == NULL)
			D_GOTO(out, rc = -DER_NOMEM);
	} else {
		crt_na_ofi_conf.noc_interface = NULL;
		D_ERROR("ENV OFI_INTERFACE not set.");
		D_GOTO(out, rc = -DER_INVAL);
	}

	rc = getifaddrs(&if_addrs);
	if (rc != 0) {
		D_ERROR("cannot getifaddrs, errno: %d(%s).\n",
			     errno, strerror(errno));
		D_GOTO(out, rc = -DER_PROTO);
	}

	for (ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, crt_na_ofi_conf.noc_interface))
			continue;
		if (ifa->ifa_addr == NULL)
			continue;
		memset(crt_na_ofi_conf.noc_ip_str, 0, INET_ADDRSTRLEN);
		if (ifa->ifa_addr->sa_family == AF_INET) {
			/* check it is a valid IPv4 Address */
			tmp_ptr =
			&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			ip_str = inet_ntop(AF_INET, tmp_ptr,
					   crt_na_ofi_conf.noc_ip_str,
					   INET_ADDRSTRLEN);
			if (ip_str == NULL) {
				D_ERROR("inet_ntop failed, errno: %d(%s).\n",
					errno, strerror(errno));
				freeifaddrs(if_addrs);
				D_GOTO(out, rc = -DER_PROTO);
			}
			/*
			 * D_DEBUG("Get interface %s IPv4 Address %s\n",
			 * ifa->ifa_name, na_ofi_conf.noc_ip_str);
			 */
			break;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			/* check it is a valid IPv6 Address */
			/*
			 * tmp_ptr =
			 * &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
			 * inet_ntop(AF_INET6, tmp_ptr, na_ofi_conf.noc_ip_str,
			 *           INET6_ADDRSTRLEN);
			 * D_DEBUG("Get %s IPv6 Address %s\n",
			 *         ifa->ifa_name, na_ofi_conf.noc_ip_str);
			 */
		}
	}
	freeifaddrs(if_addrs);
	if (ip_str == NULL) {
		D_ERROR("no IP addr found.\n");
		D_GOTO(out, rc = -DER_PROTO);
	}

	rc = crt_get_port(&port);
	if (rc != 0) {
		D_ERROR("crt_get_port failed, rc: %d.\n", rc);
		D_GOTO(out, rc);
	}

	port_str = getenv("OFI_PORT");
	if (crt_is_service() && port_str != NULL && strlen(port_str) > 0) {
		if (!is_integer_str(port_str)) {
			D_DEBUG(DB_ALL, "ignore invalid OFI_PORT %s.",
				port_str);
		} else {
			port = atoi(port_str);
			D_DEBUG(DB_ALL, "OFI_PORT %d, use it as service "
				"port.\n", port);
		}
	}
	crt_na_ofi_conf.noc_port = port;

out:
	if (rc != -DER_SUCCESS) {
		D_FREE(crt_na_ofi_conf.noc_interface);
	}
	return rc;
}

void crt_na_ofi_config_fini(void)
{
	D_FREE(crt_na_ofi_conf.noc_interface);
	crt_na_ofi_conf.noc_port = 0;
}
