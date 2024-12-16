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

/*
 * The application is to show case the unified switch model traffic
 * while matching on the Path Selector value (PSV).
 * It can be used to steer the traffic from vf to wire based on the PSVs and the spray mode.
 * User can use different packets to verify different directions of
 * traffic. The incoming traffic from VF to wire. It steers
 * the pkt based on the uplink identifier and/or PSVs written on the packet meta
 */

#include <stdlib.h>
#include <signal.h>
#include <rte_ethdev.h>
#include <doca_argp.h>
#include <doca_log.h>
#include "ip_tunnel_core.h"

DOCA_LOG_REGISTER(IP_TUNNEL::MAIN);

static struct ip_tunnel_app_config app_cfg;

/*
 * Signal handler
 *
 * @signum [in]: The signal received to handle
 */
static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		app_cfg.force_quit = true;
	}
}

/*
 * App main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	struct ip_tunnel_flow_resources app_flow_resources = {};
	int exit_status = EXIT_FAILURE;

	/* need to check if isolated mode is needed as well: port_config.isolated_mode = 1, */
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = MIN_NB_PORTS,
		.port_config.nb_queues = 1,
		.port_config.isolated_mode = 1,
		.port_config.switch_mode = 1,
		.port_config.enable_mbuf_metadata = false,
	};
	struct flow_switch_ctx ctx = {0};
	app_cfg.dpdk_config = &dpdk_config;
	app_cfg.ctx = &ctx;
	/* Register a logger backend */
	TRY_OR_GOTO(result, doca_log_backend_create_standard(), app_exit);

	/* Register a logger backend for internal SDK errors and warnings */
	TRY_OR_GOTO(result, doca_log_backend_create_with_file_sdk(stderr, &sdk_log), app_exit);
	TRY_OR_GOTO(result, doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING), app_exit);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	app_cfg.force_quit = false;
	app_cfg.stat_refresh_rate = DEFAULT_SLEEP_TIME;

	TRY_OR_GOTO(result, doca_argp_init("doca_ps_switching_switching", &app_cfg), app_exit);

	TRY_OR_GOTO(result, ip_tunnel_params_register(), app_exit);

	doca_argp_set_dpdk_program(init_flow_switch_dpdk);
	TRY_OR_GOTO(result, doca_argp_start(argc, argv), argp_cleanup);

	TRY_OR_GOTO(result, init_doca_flow_switch_common(&ctx), dpdk_cleanup);

	/* update queues and ports */
	TRY_OR_GOTO(result, dpdk_queues_and_ports_init(app_cfg.dpdk_config), dpdk_cleanup);

	TRY_OR_GOTO(result, ip_tunnel_app_init(&app_cfg, &app_flow_resources), dpdk_ports_queues_cleanup);

	TRY_OR_GOTO(result, ip_tunnel_app_create_pipeline(&app_cfg, &app_flow_resources), doca_flow_resources_cleanup);

	TRY_OR_GOTO(result, ip_tunnel_app_wait_for_signal(&app_cfg, &app_flow_resources), doca_flow_resources_cleanup);

	exit_status = EXIT_SUCCESS;

doca_flow_resources_cleanup:
	ip_tunnel_app_destroy(&app_cfg, &app_flow_resources);
dpdk_ports_queues_cleanup:
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
	dpdk_fini();
argp_cleanup:
	doca_argp_destroy();
app_exit:
	destroy_doca_flow_switch_common(&ctx);
	return exit_status;
}
