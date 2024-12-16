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

#ifndef PATH_SELECTOR_SWITCHING_PARSER_H_
#define PATH_SELECTOR_SWITCHING_PARSER_H_

#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>
#include <samples/doca_flow/flow_switch_common.h>

#define MAC_ADDR_LEN 6
#define IPV6_ADDR_LEN 16
#define MIN_NB_PORTS 2  /* Default Number of ports */
#define MAX_NB_PORTS (16)     /* Maximum number of ports */
#define IP6_FLOW_LABEL_LEN 32 /* IPv6 flow label number of bits */
#define PORT_LEN 16	      /* Port number of bits */
#define DEFAULT_SLEEP_TIME 5  /* Default sleep time */

enum spray_mode {
	ENCODE_PLANE,
	LIST_OF_PATH_SELECTORS,
	HASH
};

enum method_type {
	UDP_SRC_PORT = 1 << 0,
	IP6_LABEL = 1 << 1
};

struct ps_dport_pair {
	uint32_t path_selector; /* Path selector value */
	uint16_t dst_port;	/* Path selector equivalent destination port */
};

struct mac_addresses {
	uint8_t src[MAC_ADDR_LEN];
	uint8_t dst[MAC_ADDR_LEN];
};

struct ipv6_addresses {
	uint8_t src[IPV6_ADDR_LEN];
	uint8_t dst[IPV6_ADDR_LEN];
};

/* Application resources, such as ports, pipes and entries */
struct ip_tunnel_app_config {
	struct application_dpdk_config *dpdk_config;
	bool force_quit; /* Set when signal is received */
	struct flow_switch_ctx *ctx;

	struct {
		struct mac_addresses mac_addrs;
	} decap;

	struct {
		struct mac_addresses mac_addrs;
		struct ipv6_addresses ip_addrs;
	} encap;

	/* list of SMAC and DMAC addresses for modifying - one per uplink */
	struct mac_addresses maddresses[MAX_NB_PORTS];
	uint16_t nb_mac_addresses;
	/* Defines the field to copy path selector to - IPv6 flow label, UDP source port or both */
	uint32_t m_type;
	enum spray_mode mode; /* Spraying mode - Encode plane, List of Entropies, Hash */
	/*
	 * Array of path selectors and their equivalent destination ports.
	 * Available if the spraying mode is "List of path selectors "
	 */
	uint32_t nb_psdport_pairs;
	struct ps_dport_pair *ps_dport_arr;
	/* Sleep time between dumping statistics */
	uint32_t stat_refresh_rate;
};

/*
 * Registers all flags used by the user when running the application, such as "spray-mode" flag.
 * This is needed so that the parsing by DOCA argument parser work as expected.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t ip_tunnel_params_register(void);

#endif /* PATH_SELECTOR_SWITCHING_PARSER_H_ */
