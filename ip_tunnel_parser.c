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

#include <json-c/json.h>
#include <rte_ether.h>
#include <doca_argp.h>

#include "ip_tunnel_parser.h"
#include "ip_tunnel_core.h"
#include "utils.h"

DOCA_LOG_REGISTER(IP_TUNNEL::PARSER);

#define MAX_FILE_NAME (255) /* Maximum file name length */
#define MAC_TO_HEX_ARRAY(mac_str, mac_array) \
	do { \
		if (!sscanf(mac_str, \
			    "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", \
			    &mac_array[0], \
			    &mac_array[1], \
			    &mac_array[2], \
			    &mac_array[3], \
			    &mac_array[4], \
			    &mac_array[5])) \
			DOCA_LOG_ERR("Failed while parsing MAC address"); \
	} while (0) /* create source mac address */

#define HEX_ARRAY_TO_MAC(mac_array, mac_str) \
	do { \
		snprintf(mac_str, \
			 18, \
			 "%02x:%02x:%02x:%02x:%02x:%02x", \
			 mac_array[0], \
			 mac_array[1], \
			 mac_array[2], \
			 mac_array[3], \
			 mac_array[4], \
			 mac_array[5]); \
	} while (0)

#if 0

/*
 * Callback function for setting spray mode
 *
 * @param [in]: spray mode as a string
 * @config [out]: application context for setting the spray mode
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t spray_mode_callback(void *param, void *config)
{
	const char *mode = (char *)param;
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	if (strcmp(mode, "encode-plane") == 0)
		app_cfg->mode = ENCODE_PLANE;
	else if (strcmp(mode, "list-of-path-selectors") == 0)
		app_cfg->mode = LIST_OF_PATH_SELECTORS;
	else if (strcmp(mode, "hash") == 0)
		app_cfg->mode = HASH;
	else {
		DOCA_LOG_ERR("Spray mode should be either \"encode-plane\", \"list-of-path-selectors\" or \"hash\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_DBG("Set spray mode: %s", mode);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting method type
 *
 * @param [in]: method type as a string
 * @config [out]: application context for setting the method type
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t method_type_callback(void *param, void *config)
{
	const char *method_type = (char *)param;
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	if (strcmp(method_type, "udp-src-port") == 0)
		app_cfg->m_type = UDP_SRC_PORT;
	else if (strcmp(method_type, "ipv6-flow-label") == 0)
		app_cfg->m_type = IP6_LABEL;
	else if (strcmp(method_type, "both") == 0)
		app_cfg->m_type = (UDP_SRC_PORT | IP6_LABEL);
	else {
		DOCA_LOG_ERR("Method type should be either - \"udp-src-port\", \"ipv6-flow-label\" or \"both\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_DBG("Set method type: %s => %u", method_type, app_cfg->m_type);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting number of ports
 *
 * @param [in]: number of ports as a integer
 * @config [out]: application context for setting number of ports
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t nb_ports_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	app_cfg->dpdk_config->port_config.nb_ports = *(uint16_t *)param;
	if (app_cfg->dpdk_config->port_config.nb_ports < PS_SWITCHING_PORTS) {
		app_cfg->dpdk_config->port_config.nb_ports = PS_SWITCHING_PORTS;
		DOCA_LOG_ERR("Number of ports should be at least %u, using default number of ports: %u",
			     PS_SWITCHING_PORTS,
			     PS_SWITCHING_PORTS);
		return DOCA_ERROR_INVALID_VALUE;
	}
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting stats refresh rate
 *
 * @param [in]: stats refresh rate time (in seconds) as a integer
 * @config [out]: application context for setting the sleep time
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t stat_refresh_rate_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	app_cfg->stat_refresh_rate = *(uint *)param;
	return DOCA_SUCCESS;
}

/*
 * Check the input file size and allocate a buffer to read it
 *
 * @fp [in]: file pointer to the input rules file
 * @file_length [out]: total bytes in file
 * @json_data [out]: allocated buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t allocate_json_buffer_dynamic(FILE *fp, size_t *file_length, char **json_data)
{
	ssize_t buf_len = 0;

	/* use fseek to put file counter to the end, and calculate file length */
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len < 0) {
			DOCA_LOG_ERR("Function ftell() failed");
			return DOCA_ERROR_IO_FAILED;
		}

		/* dynamic allocation */
		*json_data = (char *)malloc(buf_len + 1);
		if (*json_data == NULL) {
			DOCA_LOG_ERR("Function malloc() failed");
			return DOCA_ERROR_NO_MEMORY;
		}

		/* return file counter to the beginning */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			free(*json_data);
			*json_data = NULL;
			DOCA_LOG_ERR("Function fseek() failed");
			return DOCA_ERROR_IO_FAILED;
		}
	}
	*file_length = buf_len;
	return DOCA_SUCCESS;
}

/*
 * Parse MAC addresses json object
 *
 * @root [in]: json config object
 * @pl [out]: parsed MAC addresses configuration.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t parse_mac_addresses_json_file(json_object *root, struct ip_tunnel_app_config *app_cfg)
{
	json_object *addresses_j, *uplink_addresses_j, *id_j, *dmac_j;
	const char *dmac;
	json_object *smac_j;
	const char *smac;
	/* Need 18 chars when printing with colon-seperated MAC address */
	char smac_addr_parsed[18];
	char dmac_addr_parsed[18];
	uint16_t uplink_id;
	uint32_t i;
	if (!json_object_object_get_ex(root, "addresses", &addresses_j)) {
		DOCA_LOG_ERR("MAC Addresses should be configured \"addresses\"");
		return DOCA_ERROR_INVALID_VALUE;
	}
	app_cfg->nb_mac_addresses = (uint16_t)json_object_array_length(addresses_j);
	if (app_cfg->nb_mac_addresses > MAX_NB_PORTS) {
		DOCA_LOG_ERR("Number of MAC addresse should not exceed maximum allowed number of ports %d",
			     MAX_NB_PORTS);
		return DOCA_ERROR_INVALID_VALUE;
	}

	for (i = 0; i < app_cfg->nb_mac_addresses; i++) {
		uplink_addresses_j = json_object_array_get_idx(addresses_j, i);

		/* Parse uplink id */
		if (!json_object_object_get_ex(uplink_addresses_j, "id", &id_j) &&
		    json_object_get_type(id_j) != json_type_int) {
			DOCA_LOG_ERR("Expecting a integer value for \"id\"");
			return DOCA_ERROR_INVALID_VALUE;
		}
		uplink_id = (uint16_t)json_object_get_int(id_j);

		/* MAC should be determined by the selected plane & the TOR respictively */

		/* Parse SMAC address */
		if (!json_object_object_get_ex(uplink_addresses_j, "smac", &smac_j) &&
		    json_object_get_type(smac_j) != json_type_string) {
			DOCA_LOG_ERR("Expecting a string value for \"smac\"");
			return DOCA_ERROR_INVALID_VALUE;
		}
		smac = json_object_get_string(smac_j);
		MAC_TO_HEX_ARRAY(smac, app_cfg->maddresses[uplink_id].src);
		HEX_ARRAY_TO_MAC(app_cfg->maddresses[uplink_id].src, smac_addr_parsed);

		/* Parse DMAC address */
		if (!json_object_object_get_ex(uplink_addresses_j, "dmac", &dmac_j) &&
		    json_object_get_type(dmac_j) != json_type_string) {
			DOCA_LOG_ERR("Expecting a string value for \"dmac\"");
			return DOCA_ERROR_INVALID_VALUE;
		}
		dmac = json_object_get_string(dmac_j);
		MAC_TO_HEX_ARRAY(dmac, app_cfg->maddresses[uplink_id].dst);
		HEX_ARRAY_TO_MAC(app_cfg->maddresses[uplink_id].dst, dmac_addr_parsed);

		DOCA_LOG_INFO("Uplink id %u has the MAC addresses modificatio actions: smac = %s , dmac = %s",
			      uplink_id,
			      smac_addr_parsed,
			      dmac_addr_parsed);
	}
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle MAC addresses JSON file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t mac_addrsses_callback(void *param, void *config)
{
	doca_error_t result;
	const char *json_path = (char *)param;
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *root;

	if (strnlen(json_path, MAX_FILE_NAME) == MAX_FILE_NAME) {
		DOCA_LOG_ERR("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	json_fp = fopen(json_path, "r");
	if (json_fp == NULL) {
		DOCA_LOG_ERR("JSON file open failed");
		return DOCA_ERROR_NOT_PERMITTED;
	}

	result = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (result != DOCA_SUCCESS) {
		fclose(json_fp);
		DOCA_LOG_ERR("Failed to allocate data buffer for the json file");
		return result;
	}

	if (fread(json_data, 1, file_length, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);
	root = json_tokener_parse(json_data);

	result = parse_mac_addresses_json_file(root, app_cfg);
	if (result != DOCA_SUCCESS) {
		doca_argp_destroy();
		DOCA_LOG_ERR("MAC addresses parsing failure");
	}

	return result;
}

/*
 * Parse MAC addresses json object
 *
 * @root [in]: json config object
 * @pl [out]: parsed MAC addresses configuration.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t parse_list_of_path_selectors_json_file(json_object *root, struct ip_tunnel_app_config *app_cfg)
{
	json_object *path_selectors, *path_selector_j, *uplink_j, *pair;
	uint32_t i;
	if (!json_object_object_get_ex(root, "path_selectors", &path_selectors)) {
		DOCA_LOG_ERR("Path selectors should be cponfigured \"path_selectors\"");
		return DOCA_ERROR_INVALID_VALUE;
	}
	app_cfg->nb_psdport_pairs = (uint16_t)json_object_array_length(path_selectors);
	if (!app_cfg->nb_mac_addresses) {
		DOCA_LOG_ERR("Number of path selectors should not be zero");
		return DOCA_ERROR_INVALID_VALUE;
	}

	app_cfg->ps_dport_arr = calloc(app_cfg->nb_psdport_pairs, sizeof(struct ps_dport_pair));
	for (i = 0; i < app_cfg->nb_psdport_pairs; i++) {
		pair = json_object_array_get_idx(path_selectors, i);

		/* Parse uplink id */
		if (!json_object_object_get_ex(pair, "id", &uplink_j) &&
		    json_object_get_type(uplink_j) != json_type_int) {
			DOCA_LOG_ERR("Expecting a integer value for \"id\"");
			return DOCA_ERROR_INVALID_VALUE;
		}
		app_cfg->ps_dport_arr[i].dst_port = (uint16_t)json_object_get_int(uplink_j);

		/* Parse path selector value */
		if (!json_object_object_get_ex(pair, "path_selector", &path_selector_j) &&
		    json_object_get_type(path_selector_j) != json_type_int) {
			DOCA_LOG_ERR("Expecting a integer value for \"path_selector\"");
			return DOCA_ERROR_INVALID_VALUE;
		}
		app_cfg->ps_dport_arr[i].path_selector = (uint32_t)json_object_get_int(path_selector_j);

		DOCA_LOG_INFO("path selector value %u should be forwarded to uplink id %u",
			      app_cfg->ps_dport_arr[i].path_selector,
			      app_cfg->ps_dport_arr[i].dst_port);
	}
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle list of path selectors JSON file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t list_of_path_selectors_callback(void *param, void *config)
{
	doca_error_t result;
	const char *json_path = (char *)param;
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *root;

	if (strnlen(json_path, MAX_FILE_NAME) == MAX_FILE_NAME) {
		DOCA_LOG_ERR("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	json_fp = fopen(json_path, "r");
	if (json_fp == NULL) {
		DOCA_LOG_ERR("JSON file open failed");
		return DOCA_ERROR_NOT_PERMITTED;
	}

	result = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (result != DOCA_SUCCESS) {
		fclose(json_fp);
		DOCA_LOG_ERR("Failed to allocate data buffer for the json file");
		return result;
	}

	if (fread(json_data, 1, file_length, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);
	root = json_tokener_parse(json_data);

	result = parse_list_of_path_selectors_json_file(root, app_cfg);
	if (result != DOCA_SUCCESS) {
		doca_argp_destroy();
		DOCA_LOG_ERR("List of path selectors parsing failure");
	}

	return result;
}

#endif

static doca_error_t handle_mac_addr_callback(void *param, uint8_t *app_cfg_mac_addr, const char *param_name)
{
	char *addr_str = (char *)param;
	struct rte_ether_addr ether_addr = {};

	if (rte_ether_unformat_addr(addr_str, &ether_addr) != 0) {
		DOCA_LOG_ERR("%s: Malformed mac addr: %s", param_name, addr_str);
		return DOCA_ERROR_INVALID_VALUE;
	}

	memcpy(app_cfg_mac_addr, ether_addr.addr_bytes, MAC_ADDR_LEN);
	DOCA_LOG_INFO("%s: %s", param_name, addr_str);
	return DOCA_SUCCESS;
}

static doca_error_t decap_smac_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_mac_addr_callback(param, app_cfg->decap.mac_addrs.src, "Decap SRC MAC");
}

static doca_error_t decap_dmac_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_mac_addr_callback(param, app_cfg->decap.mac_addrs.dst, "Decap DST MAX");
}

static doca_error_t encap_smac_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_mac_addr_callback(param, app_cfg->encap.mac_addrs.src, "Encap SRC MAC");
}

static doca_error_t encap_dmac_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_mac_addr_callback(param, app_cfg->encap.mac_addrs.dst, "Encap DST MAC");
}

static doca_error_t handle_ipv6_addr_callback(void *param, uint8_t *app_cfg_addr, const char *param_name)
{

	char *addr_str = (char *)param;

	if (inet_pton(AF_INET6, addr_str, app_cfg_addr) != 1) {
		DOCA_LOG_ERR("%s: Malformed IPv6 addr: %s", param_name, addr_str);
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_INFO("%s: %s", param_name, addr_str);
	return DOCA_SUCCESS;
}

static doca_error_t encap_sip_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_ipv6_addr_callback(param, app_cfg->encap.ip_addrs.src, "Encap SRC IP");
}

static doca_error_t encap_dip_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	return handle_ipv6_addr_callback(param, app_cfg->encap.ip_addrs.dst, "Encap DST IP");
}

/*
 * Get DOCA Flow switch device PCI
 *
 * @param [in]: input parameter
 * @config [out]: configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t ps_switching_param_flow_switch_pci_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	struct flow_switch_ctx *ctx = app_cfg->ctx;
	char *n = (char *)param;

	ctx->dev_arg[ctx->nb_ports++] = n;

	return DOCA_SUCCESS;
}

/*
 * Get DOCA Flow switch device representor
 *
 * @param [in]: input parameter
 * @config [out]: configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t ps_switching_param_flow_switch_rep_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	struct flow_switch_ctx *ctx = app_cfg->ctx;
	char *n = (char *)param;

	ctx->rep_arg[ctx->nb_reps++] = n;

	return DOCA_SUCCESS;
}

/*
 * Get DOCA Flow switch mode
 *
 * @param [in]: input parameter
 * @config [out]: configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t ps_switching_param_flow_switch_exp_callback(void *param, void *config)
{
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;
	struct flow_switch_ctx *ctx = app_cfg->ctx;

	ctx->is_expert = *(bool *)param;

	return DOCA_SUCCESS;
}

/*
 * Validate received parameters
 *
 * @config [in]: configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t app_params_validation_callback(void *config)
{
#if 0
	struct ip_tunnel_app_config *app_cfg = (struct ip_tunnel_app_config *)config;

	if (app_cfg->nb_mac_addresses != app_cfg->dpdk_config->port_config.nb_ports) {
		DOCA_LOG_ERR("Number of MAC addresses should be the same as number of ports");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!app_cfg->nb_psdport_pairs && app_cfg->mode == LIST_OF_PATH_SELECTORS) {
		DOCA_LOG_ERR("List of path selectors should be provided in this mode");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (app_cfg->nb_psdport_pairs && app_cfg->mode != LIST_OF_PATH_SELECTORS) {
		DOCA_LOG_ERR("List of path selectors should not be provided in HASH or Encode-plane modes");
		return DOCA_ERROR_INVALID_VALUE;
	}
#endif
	return DOCA_SUCCESS;
}

/*
 * Register DOCA Flow switch parameter
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t ps_switching_register_doca_flow_switch_param(void)
{
	doca_error_t result;
	struct doca_argp_param *pci_param;
	struct doca_argp_param *rep_param;
	struct doca_argp_param *exp_param;

	TRY_OR_GOTO(result, doca_argp_param_create(&pci_param), cleanup);
	doca_argp_param_set_short_name(pci_param, "p");
	doca_argp_param_set_long_name(pci_param, "pci");
	doca_argp_param_set_description(pci_param, "device PCI address");
	doca_argp_param_set_callback(pci_param, ps_switching_param_flow_switch_pci_callback);
	doca_argp_param_set_type(pci_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(pci_param);
	doca_argp_param_set_multiplicity(pci_param);
	TRY_OR_GOTO(result, doca_argp_register_param(pci_param), cleanup);

	TRY_OR_GOTO(result, doca_argp_param_create(&rep_param), cleanup);
	doca_argp_param_set_short_name(rep_param, "r");
	doca_argp_param_set_long_name(rep_param, "rep");
	doca_argp_param_set_description(rep_param, "device representor");
	doca_argp_param_set_callback(rep_param, ps_switching_param_flow_switch_rep_callback);
	doca_argp_param_set_type(rep_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rep_param);
	doca_argp_param_set_multiplicity(rep_param);
	TRY_OR_GOTO(result, doca_argp_register_param(rep_param), cleanup);

	TRY_OR_GOTO(result, doca_argp_param_create(&exp_param), cleanup);
	doca_argp_param_set_short_name(exp_param, "exp");
	doca_argp_param_set_long_name(exp_param, "expert-mode");
	doca_argp_param_set_description(exp_param, "set expert mode");
	doca_argp_param_set_callback(exp_param, ps_switching_param_flow_switch_exp_callback);
	doca_argp_param_set_type(exp_param, DOCA_ARGP_TYPE_BOOLEAN);
	TRY_OR_GOTO(result, doca_argp_register_param(exp_param), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}

doca_error_t create_param(const char *short_name,
			  const char *long_name,
			  enum doca_argp_type param_type,
			  doca_argp_param_cb_t callback,
			  bool required,
			  bool allow_multiple,
			  const char *desc)
{
	doca_error_t result;
	struct doca_argp_param *param;
	TRY_OR_GOTO(result, doca_argp_param_create(&param), cleanup);
	doca_argp_param_set_short_name(param, short_name);
	doca_argp_param_set_long_name(param, long_name);
	doca_argp_param_set_description(param, desc);
	doca_argp_param_set_callback(param, callback);
	doca_argp_param_set_type(param, param_type);
	if (required)
		doca_argp_param_set_mandatory(param);
	if (allow_multiple)
		doca_argp_param_set_multiplicity(param);
	TRY_OR_GOTO(result, doca_argp_register_param(param), cleanup);

cleanup:
	return result;
}

doca_error_t ip_tunnel_params_register(void)
{
	doca_error_t result;

	TRY_OR_GOTO(result, ps_switching_register_doca_flow_switch_param(), cleanup);

	TRY_OR_GOTO(result,
		    create_param("ds",
				 "decap-smac",
				 DOCA_ARGP_TYPE_STRING,
				 decap_smac_callback,
				 true,
				 false,
				 "The src MAC address sent to the VF after the outer IPv6 header is decapped"),
		    cleanup);
	TRY_OR_GOTO(result,
		    create_param("dd",
				 "decap-dmac",
				 DOCA_ARGP_TYPE_STRING,
				 decap_dmac_callback,
				 true,
				 false,
				 "The dest MAC address sent to the VF after the outer IPv6 header is decapped"),
		    cleanup);

	TRY_OR_GOTO(result,
		    create_param("es",
				 "encap-smac",
				 DOCA_ARGP_TYPE_STRING,
				 encap_smac_callback,
				 true,
				 false,
				 "The src MAC address sent to the wire after the outer IPv6 header is encapped"),
		    cleanup);
	TRY_OR_GOTO(result,
		    create_param("ed",
				 "encap-dmac",
				 DOCA_ARGP_TYPE_STRING,
				 encap_dmac_callback,
				 true,
				 false,
				 "The dest MAC address sent to the wire after the outer IPv6 header is encapped"),
		    cleanup);

	TRY_OR_GOTO(result,
		    create_param("sip",
				 "encap-sip",
				 DOCA_ARGP_TYPE_STRING,
				 encap_sip_callback,
				 true,
				 false,
				 "The src IP address sent to the wire after the outer IPv6 header is encapped"),
		    cleanup);
	TRY_OR_GOTO(result,
		    create_param("dip",
				 "encap-dip",
				 DOCA_ARGP_TYPE_STRING,
				 encap_dip_callback,
				 true,
				 false,
				 "The dest IP address sent to the wire after the outer IPv6 header is encapped"),
		    cleanup);
#if 0
	/* Create and register number of ports param */
	result = doca_argp_param_create(&nb_ports);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(nb_ports, "np");
	doca_argp_param_set_long_name(nb_ports, "nb-ports");
	doca_argp_param_set_description(nb_ports, "Set number of ports");
	doca_argp_param_set_callback(nb_ports, nb_ports_callback);
	doca_argp_param_set_type(nb_ports, DOCA_ARGP_TYPE_INT);
	doca_argp_param_set_mandatory(nb_ports);
	result = doca_argp_register_param(nb_ports);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register number of ports param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register spray mode param */
	result = doca_argp_param_create(&spray_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(spray_mode, "s");
	doca_argp_param_set_long_name(spray_mode, "spray-mode");
	doca_argp_param_set_description(spray_mode,
					"Set spraying mode - \"encode-plane\", \"list-of-path-selectors\" or \"hash\"");
	doca_argp_param_set_callback(spray_mode, spray_mode_callback);
	doca_argp_param_set_type(spray_mode, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(spray_mode);
	result = doca_argp_register_param(spray_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register spray param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register MAC addresses param */
	result = doca_argp_param_create(&mac_addrsses_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(mac_addrsses_param, "m");
	doca_argp_param_set_long_name(mac_addrsses_param, "mac-addresses");
	doca_argp_param_set_description(mac_addrsses_param, "Set MAC addresses file path");
	doca_argp_param_set_callback(mac_addrsses_param, mac_addrsses_callback);
	doca_argp_param_set_type(mac_addrsses_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(mac_addrsses_param);
	result = doca_argp_register_param(mac_addrsses_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register MAC addresses file path param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register stats refresh time */
	result = doca_argp_param_create(&stat_refresh_rate);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(stat_refresh_rate, "t");
	doca_argp_param_set_long_name(stat_refresh_rate, "stats-rate");
	doca_argp_param_set_description(stat_refresh_rate, "Set stats refresh rate time (in seconds)");
	doca_argp_param_set_callback(stat_refresh_rate, stat_refresh_rate_callback);
	doca_argp_param_set_type(stat_refresh_rate, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(stat_refresh_rate);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register stats refresh rate time param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register list of path selector param */
	result = doca_argp_param_create(&ps_list);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(ps_list, "e");
	doca_argp_param_set_long_name(ps_list, "list-of-path-selectors");
	doca_argp_param_set_description(ps_list, "Set Set list of path selectors file path");
	doca_argp_param_set_callback(ps_list, list_of_path_selectors_callback);
	doca_argp_param_set_type(ps_list, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(ps_list);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register list of path selectors param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register spray mode param */
	result = doca_argp_param_create(&method_type);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(method_type, "mt");
	doca_argp_param_set_long_name(method_type, "method-type");
	doca_argp_param_set_description(method_type,
					"Set method type - \"udp-src-port\", \"ipv6-flow-label\" or \"both\"");
	doca_argp_param_set_callback(method_type, method_type_callback);
	doca_argp_param_set_type(method_type, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(method_type);
	result = doca_argp_register_param(method_type);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register method type param: %s", doca_error_get_descr(result));
		return result;
	}
#endif

	/* Register validation callback */
	TRY_OR_GOTO(result, doca_argp_register_validation_callback(app_params_validation_callback), cleanup);

	/* Register version callback for DOCA SDK & RUNTIME */
	TRY_OR_GOTO(result, doca_argp_register_version_callback(sdk_version_callback), cleanup);

	return DOCA_SUCCESS;

cleanup:
	return result;
}
