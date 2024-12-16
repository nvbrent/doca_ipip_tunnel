/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef IP_TUNNEL_CORE_H_
#define IP_TUNNEL_CORE_H_
#include <doca_flow.h>
#include <doca_dev.h>
#include "ip_tunnel_parser.h"

#define TRY_OR_GOTO(result, statement, label) \
	{ \
		result = statement; \
		if (result != DOCA_SUCCESS) { \
			DOCA_LOG_ERR("Failure in %s: %s", #statement, doca_error_get_descr(result)); \
			goto label; \
		} \
	}

#define MAX_ENTRIES (2)
#define MAX_COPY_OPS (8)

struct pipe_entries {
	const char *name;
	struct doca_flow_port *port;
	struct doca_flow_pipe *pipe;
	uint32_t nb_entries;
	struct doca_flow_pipe_entry *entries[MAX_ENTRIES];
	bool has_entry_counters;
	bool has_miss_counter;
	bool error_reported;
};

struct application_pipes
{
	union {
		struct {
			struct pipe_entries root_pipe; /* separates ingress vs. egress traffic pipe */
			struct pipe_entries set_meta_pipe;
			struct pipe_entries encap_pipe;
			struct pipe_entries set_outer_dst_ip_pipe;
			struct pipe_entries to_uplink;
			struct pipe_entries decap_pipe;
		};
		struct pipe_entries as_array[0];
	};
};
#define NB_PIPES sizeof(struct application_pipes) / sizeof(struct pipe_entries)

/* DOCA flow application resources, such as ports, pipes and entries */
struct ip_tunnel_flow_resources {
	struct doca_flow_port *ports[MAX_NB_PORTS]; /* DOCA Flow ports array used by the application */
	struct application_pipes pipes;
};

struct copy_op {
	uint16_t src_start_bit;
	uint16_t dst_start_bit;
	uint16_t nb_bits;
};

/*
 * Initialize DOCA flow and application components
 *
 * @app_cfg [in]: application configuration as parsed from the CLI
 * @app_flow_resources [out]: contains different DOCA flow components
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t ip_tunnel_app_init(struct ip_tunnel_app_config *app_cfg,
				struct ip_tunnel_flow_resources *app_flow_resources);

/*
 * Create pipeline based on the spray mode
 *
 * @app_cfg [in]: application configuration as parsed from the CLI
 * @app_flow_resources [in/out]: contains different DOCA flow components
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t ip_tunnel_app_create_pipeline(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources);

/*
 * Wait until signal is received and dump statistics
 *
 * @app_cfg [in]: application configuration as parsed from the CLI
 * @app_flow_resources [in]: contains different DOCA flow components
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t ip_tunnel_app_wait_for_signal(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources);

/*
 * DOCA flow and application components.
 *
 * @app_cfg [in]: application configuration as parsed from the CLI
 * @app_flow_resources [out]: contains different DOCA flow components
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t ip_tunnel_app_destroy(struct ip_tunnel_app_config *app_cfg,
				   struct ip_tunnel_flow_resources *app_flow_resources);

#endif /* IP_TUNNEL_CORE_H_ */
