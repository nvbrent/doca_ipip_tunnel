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

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <doca_bitfield.h>

#include <samples/common.h>
#include <samples/doca_flow/flow_common.h>
#include "ip_tunnel_core.h"

#define META_U32_BIT_OFFSET(idx) (offsetof(struct doca_flow_meta, u32[(idx)]) << 3)
#define SECOND (1)
#define MAC_ADDR_MASK 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
#define IPV6_ADDR_MASK UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX

DOCA_LOG_REGISTER(IP_TUNNEL::CORE);

struct doca_flow_monitor mon_non_shared_cntr = {
	.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
};

struct doca_flow_fwd fwd_drop = {
	.type = DOCA_FLOW_FWD_DROP,
};

doca_error_t ip_tunnel_app_init(struct ip_tunnel_app_config *app_cfg,
				struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct flow_resources resource = {0};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_dev *dev_arr[MAX_NB_PORTS];
	uint32_t actions_mem_size[MAX_NB_PORTS];
	uint16_t nb_ports = app_cfg->dpdk_config->port_config.nb_ports;
	doca_error_t result;

	resource.nr_counters = NB_PIPES * MAX_ENTRIES;
	TRY_OR_GOTO(result,
		    init_doca_flow(app_cfg->dpdk_config->port_config.nb_queues,
				   "switch,hws,isolated,disable_switch_rss",
				   &resource,
				   nr_shared_resources),
		    cleanup);

	memset(dev_arr, 0, sizeof(struct doca_dev *) * nb_ports);
	dev_arr[0] = app_cfg->ctx->doca_dev[0];
	ARRAY_INIT(actions_mem_size,
		   ACTIONS_MEM_SIZE(app_cfg->dpdk_config->port_config.nb_queues, NB_PIPES * MAX_ENTRIES));
	TRY_OR_GOTO(result,
		    init_doca_flow_ports(nb_ports, app_flow_resources->ports, false, dev_arr, actions_mem_size),
		    cleanup);

	return DOCA_SUCCESS;
cleanup:
	return result;
}

static doca_error_t process_entries(struct pipe_entries *pipe, struct entries_status *status)
{
	doca_error_t result = doca_flow_entries_process(pipe->port, 0, DEFAULT_TIMEOUT_US, pipe->nb_entries);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process pipe entries: %s", doca_error_get_descr(result));
		return result;
	}

	if (status->nb_processed != pipe->nb_entries || status->failure) {
		DOCA_LOG_ERR("Failed to process pipe entries; nb_processed = %d, expected %d, failure = %d",
			     status->nb_processed,
			     pipe->nb_entries,
			     status->failure);
		return DOCA_ERROR_BAD_STATE;
	}

	return DOCA_SUCCESS;
}

static doca_error_t root_pipe_build(struct ip_tunnel_app_config *app_cfg,
				    struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.root_pipe;
	pipe->name = "ROOT_PIPE";
	pipe->nb_entries = 2;
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->has_entry_counters = true;
	pipe->has_miss_counter = false;

	doca_error_t result;

	struct doca_flow_match match = {
		.parser_meta.port_meta = -1, /* per entry */
	};
	struct doca_flow_match match_mask = {
		.parser_meta.port_meta = -1,
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = NULL, /* per entry */
	};

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, true), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &match_mask), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mon_non_shared_cntr), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_drop, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t root_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					  struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.root_pipe;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;

	struct doca_flow_match match = {
		.parser_meta.port_meta = 0, /* uplink */
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = app_flow_resources->pipes.decap_pipe.pipe,
	};
	assert(fwd.next_pipe);
	TRY_OR_GOTO(
		result,
		doca_flow_pipe_add_entry(0, pipe->pipe, &match, NULL, NULL, &fwd, flags, &status, &pipe->entries[0]),
		cleanup);

	flags = DOCA_FLOW_NO_WAIT;
	match.parser_meta.port_meta = 1; /* VF */
	fwd.next_pipe = app_flow_resources->pipes.set_meta_pipe.pipe;
	TRY_OR_GOTO(
		result,
		doca_flow_pipe_add_entry(0, pipe->pipe, &match, NULL, NULL, &fwd, flags, &status, &pipe->entries[1]),
		cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static doca_error_t decap_pipe_build(struct ip_tunnel_app_config *app_cfg,
				     struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.decap_pipe;
	pipe->name = "DECAP_PIPE";
	pipe->nb_entries = 1;
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->has_entry_counters = true;
	pipe->has_miss_counter = true;

	doca_error_t result;

	struct doca_flow_match match = {
		.outer =
			{
				.l3_type = DOCA_FLOW_L3_TYPE_IP6,
				.ip6 =
					{
						.next_proto = IPPROTO_IPIP,
					},
			},
	};
	struct doca_flow_actions actions = {
		.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.decap_cfg =
			{
				.eth =
					{
						.src_mac = {MAC_ADDR_MASK},
						.dst_mac = {MAC_ADDR_MASK},
						.type = DOCA_HTOBE16(DOCA_FLOW_ETHER_TYPE_IPV4),
					},
			},
	};
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = 1, /* VF */
	};

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, false), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mon_non_shared_cntr), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_drop, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t decap_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.decap_pipe;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;

	struct doca_flow_actions actions = {
		.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
	};
	memcpy(actions.decap_cfg.eth.src_mac, app_cfg->decap.mac_addrs.src, MAC_ADDR_LEN);
	memcpy(actions.decap_cfg.eth.dst_mac, app_cfg->decap.mac_addrs.dst, MAC_ADDR_LEN);

	TRY_OR_GOTO(
		result,
		doca_flow_pipe_add_entry(0, pipe->pipe, NULL, &actions, NULL, NULL, flags, &status, &pipe->entries[0]),
		cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static doca_error_t set_meta_pipe_build(struct ip_tunnel_app_config *app_cfg,
					struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.set_meta_pipe;
	pipe->name = "SET_META_PIPE";
	pipe->nb_entries = 1;
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->has_entry_counters = true;

	doca_error_t result;

	struct doca_flow_match match = {};

	struct doca_flow_actions actions = {
		.meta = {.pkt_meta = UINT32_MAX},
	};
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = app_flow_resources->pipes.encap_pipe.pipe,
	};
	assert(fwd.next_pipe);

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, false), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mon_non_shared_cntr), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t set_meta_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					      struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.set_meta_pipe;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;

	struct doca_flow_actions actions = {
		.meta = {.pkt_meta = DOCA_HTOBE32(0xAABBCCDD)},
	};

	TRY_OR_GOTO(
		result,
		doca_flow_pipe_add_entry(0, pipe->pipe, NULL, &actions, NULL, NULL, flags, &status, &pipe->entries[0]),
		cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static doca_error_t encap_pipe_build(struct ip_tunnel_app_config *app_cfg,
				     struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.encap_pipe;
	pipe->name = "ENCAP_PIPE";
	pipe->nb_entries = 1;
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->has_entry_counters = true;
	pipe->has_miss_counter = true;

	doca_error_t result;

	struct doca_flow_match match = {};

	struct doca_flow_header_eth eth_action_mask = {
		.src_mac = {MAC_ADDR_MASK},
		.dst_mac = {MAC_ADDR_MASK},
		.type = DOCA_HTOBE16(DOCA_FLOW_ETHER_TYPE_IPV6),
	};
	struct doca_flow_header_ip6 ipv6_action_mask = {
		.src_ip = {IPV6_ADDR_MASK},
		.dst_ip = {IPV6_ADDR_MASK},
		.next_proto = IPPROTO_IPIP,
		.hop_limit = 10,
		.flow_label = 0,
		.traffic_class = 0,
	};
	struct doca_flow_actions actions = {
		.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
	};
	actions.encap_cfg.encap.outer.eth = eth_action_mask;
	actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6;
	actions.encap_cfg.encap.outer.ip6 = ipv6_action_mask;
	actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_IP_IN_IP;
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = app_flow_resources->pipes.set_outer_dst_ip_pipe.pipe,
	};
	assert(fwd.next_pipe);

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, false), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mon_non_shared_cntr), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_drop, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t encap_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.encap_pipe;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;

	struct doca_flow_actions actions = {};
	memcpy(actions.encap_cfg.encap.outer.eth.src_mac, app_cfg->encap.mac_addrs.src, MAC_ADDR_LEN);
	memcpy(actions.encap_cfg.encap.outer.eth.dst_mac, app_cfg->encap.mac_addrs.dst, MAC_ADDR_LEN);
	memcpy(actions.encap_cfg.encap.outer.ip6.src_ip, app_cfg->encap.ip_addrs.src, IPV6_ADDR_LEN);
	memcpy(actions.encap_cfg.encap.outer.ip6.dst_ip, app_cfg->encap.ip_addrs.dst, IPV6_ADDR_LEN);

	TRY_OR_GOTO(
		result,
		doca_flow_pipe_add_entry(0, pipe->pipe, NULL, &actions, NULL, NULL, flags, &status, &pipe->entries[0]),
		cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static struct doca_flow_action_desc *format_copy_desc(struct copy_op *op, struct doca_flow_action_desc *desc)
{
	desc->type = DOCA_FLOW_ACTION_COPY;
	desc->field_op.src.field_string = "meta.data";
	desc->field_op.src.bit_offset = op->src_start_bit;
	desc->field_op.dst.field_string = "outer.ipv6.dst_ip";
	desc->field_op.dst.bit_offset = op->dst_start_bit ^ 64;
	desc->field_op.width = op->nb_bits;
	DOCA_LOG_INFO("action_desc: src = %s, offset %d, dst = %s, offset %d, width %d",
		      desc->field_op.src.field_string,
		      desc->field_op.src.bit_offset,
		      desc->field_op.dst.field_string,
		      desc->field_op.dst.bit_offset,
		      desc->field_op.width);
	return desc;
}

static doca_error_t dest_ip_pipe_build(struct ip_tunnel_app_config *app_cfg,
				       struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.set_outer_dst_ip_pipe;
	pipe->name = "SET_DST_IP_PIPE";
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->nb_entries = 1;
	doca_error_t result;

	struct doca_flow_match match = {};

	struct copy_op ps_copy_ops[] = {
		// src, dst, len
		{0, 64, 8},
		{8, 80, 8},
		{16, 96, 8},
		{24, 112, 8},
	};
	uint32_t nr_ps_bit_copies = sizeof(ps_copy_ops) / sizeof(ps_copy_ops[0]);

	struct doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = app_flow_resources->pipes.to_uplink.pipe;
	assert(fwd.next_pipe);

	struct doca_flow_fwd fwd_miss = fwd; /* same next_pipe for fwd and fwd_miss */

	struct doca_flow_action_desc ps_copy_action_array[nr_ps_bit_copies];
	memset(ps_copy_action_array, 0, sizeof(ps_copy_action_array));

	for (uint32_t i = 0; i < nr_ps_bit_copies; i++) {
		format_copy_desc(&ps_copy_ops[i], &ps_copy_action_array[i]);
	}

	struct doca_flow_action_descs ps_copy_actions = {
		.nb_action_desc = nr_ps_bit_copies,
		.desc_array = ps_copy_action_array,
	};
	struct doca_flow_action_descs *action_descs_array[] = {&ps_copy_actions};

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, false), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, NULL, NULL, action_descs_array, 1), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t dest_ip_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					     struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.set_outer_dst_ip_pipe;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;

	TRY_OR_GOTO(result,
		    doca_flow_pipe_add_entry(0, pipe->pipe, NULL, NULL, NULL, NULL, flags, &status, &pipe->entries[0]),
		    cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static doca_error_t to_uplink_pipe_build(struct ip_tunnel_app_config *app_cfg,
					 struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.to_uplink;
	pipe->name = "TO_UPLINK_PIPE";
	pipe->nb_entries = 1;
	pipe->port = doca_flow_port_switch_get(app_flow_resources->ports[0]);
	pipe->has_entry_counters = true;

	doca_error_t result;

	struct doca_flow_match match = {};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = 0, /* uplink */
	};

	struct doca_flow_pipe_cfg *pipe_cfg;
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_create(&pipe_cfg, pipe->port), cleanup);
	TRY_OR_GOTO(result, set_flow_pipe_cfg(pipe_cfg, pipe->name, DOCA_FLOW_PIPE_BASIC, false), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, pipe->nb_entries), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mon_non_shared_cntr), cleanup);
	TRY_OR_GOTO(result, doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &pipe->pipe), cleanup);
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	return DOCA_SUCCESS;

cleanup:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t to_uplink_pipe_add_entries(struct ip_tunnel_app_config *app_cfg,
					       struct ip_tunnel_flow_resources *app_flow_resources)
{
	struct pipe_entries *pipe = &app_flow_resources->pipes.to_uplink;

	doca_error_t result;
	struct entries_status status = {};
	enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;

	TRY_OR_GOTO(result,
		    doca_flow_pipe_add_entry(0, pipe->pipe, NULL, NULL, NULL, NULL, flags, &status, &pipe->entries[0]),
		    cleanup);

	TRY_OR_GOTO(result, process_entries(pipe, &status), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

doca_error_t ip_tunnel_app_create_pipeline(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources)
{
	doca_error_t result;

	TRY_OR_GOTO(result, decap_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, decap_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	TRY_OR_GOTO(result, to_uplink_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, to_uplink_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	TRY_OR_GOTO(result, dest_ip_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, dest_ip_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	TRY_OR_GOTO(result, encap_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, encap_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	TRY_OR_GOTO(result, set_meta_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, set_meta_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	TRY_OR_GOTO(result, root_pipe_build(app_cfg, app_flow_resources), cleanup);
	TRY_OR_GOTO(result, root_pipe_add_entries(app_cfg, app_flow_resources), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

static void dump_application_pipe_stats(struct pipe_entries pipes[], uint32_t nb_pipes)
{
	for (uint32_t i = 0; i < nb_pipes; i++) {
		struct pipe_entries *pipe = &pipes[i];
		if (!pipe->has_entry_counters || pipe->error_reported) {
			DOCA_LOG_INFO("Pipe %s: skipped", pipe->name);
			continue;
		}
		struct doca_flow_resource_query query_stats = {};
		DOCA_LOG_INFO("Pipe %s:", pipe->name);
		for (uint32_t j = 0; j < pipe->nb_entries; j++) {
			doca_error_t result = doca_flow_resource_query_entry(pipe->entries[j], &query_stats);
			if (result == DOCA_SUCCESS) {
				DOCA_LOG_INFO("- Entry %d: %ld hits", j, query_stats.counter.total_pkts);
			} else {
				DOCA_LOG_ERR("- Entry %d: failed to query entry: %s", j, doca_error_get_descr(result));
				pipe->error_reported = true;
			}
		}
		if (pipe->has_miss_counter) {
			doca_error_t result = doca_flow_resource_query_pipe_miss(pipe->pipe, &query_stats);
			if (result == DOCA_SUCCESS) {
				DOCA_LOG_INFO("- Miss: %ld hits", query_stats.counter.total_pkts);
			} else {
				DOCA_LOG_ERR("- Miss: failed to query entry: %s", doca_error_get_descr(result));
				pipe->error_reported = true;
			}
		}
	}
}

doca_error_t ip_tunnel_app_wait_for_signal(struct ip_tunnel_app_config *app_cfg,
					   struct ip_tunnel_flow_resources *app_flow_resources)
{
	uint32_t count = 0;
	while (!app_cfg->force_quit) {
		sleep(SECOND);
		count++;
		if (count >= app_cfg->stat_refresh_rate) {
			dump_application_pipe_stats(app_flow_resources->pipes.as_array, NB_PIPES);
			count = 0;
		}
	}
	return DOCA_SUCCESS;
}

doca_error_t ip_tunnel_app_destroy(struct ip_tunnel_app_config *app_cfg,
				   struct ip_tunnel_flow_resources *app_flow_resources)
{
	doca_error_t result;
	uint16_t nb_ports = app_cfg->dpdk_config->port_config.nb_ports;

	TRY_OR_GOTO(result, stop_doca_flow_ports(nb_ports, app_flow_resources->ports), cleanup);
cleanup:

	doca_flow_destroy();
	if (app_cfg->ps_dport_arr)
		free(app_cfg->ps_dport_arr);
	return DOCA_SUCCESS;
}