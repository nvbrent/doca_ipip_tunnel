#
# Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('ip_tunnel', 'C', 'CPP',
	version: '0.0.1',
	default_options: ['buildtype=debug']
)

APP_NAME = meson.project_name()
DOCA_PREFIX = 'doca_'
apps_common_c_args = ''
apps_common_cpp_args = ''
grpc_cpp_args = ''

add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: 'c')
add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: 'cpp')

dependency_libdpdk = dependency('libdpdk', required : false)
if not dependency_libdpdk.found()
	error('Please set PKG_CONFIG_PATH to DPDK packages path, for further instructions please refer to the DOCA Reference Applications guide')
endif
app_dependencies = [dependency_libdpdk]
app_dependencies += dependency('json-c', required : true)
app_dependencies += dependency('threads', required : true)

app_dependencies += dependency('doca-common', required : true)
app_dependencies += dependency('doca-argp', required : true)
app_dependencies += dependency('doca-flow', required : true)
app_dependencies += dependency('doca-dpdk-bridge', required : true)

doca_root_dir = dependency('doca-common').get_variable('prefix', default_value: '/opt/mellanox/doca')

common_dir_path = doca_root_dir + '/applications/common'
samples_dir_path = doca_root_dir + '/samples'

app_inc_dirs = [include_directories(common_dir_path, doca_root_dir, samples_dir_path)]

app_srcs = files([
	APP_NAME + '.c',
	APP_NAME + '_core.c',
	APP_NAME + '_parser.c',
	common_dir_path + '/dpdk_utils.c',
	common_dir_path + '/pack.c',
	common_dir_path + '/utils.c',
	common_dir_path + '/flow_parser.c',
	doca_root_dir + '/samples/common.c',
	samples_dir_path + '/doca_flow/flow_common.c',
	samples_dir_path + '/doca_flow/flow_switch_common.c',
])

executable(DOCA_PREFIX + APP_NAME, app_srcs,
	c_args : apps_common_c_args,
    cpp_args: apps_common_cpp_args,
	dependencies : app_dependencies,
	include_directories: app_inc_dirs)