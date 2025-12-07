**freebox-monitoring**

# List of metrics and tags output

## Tags on all metrics

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox* | api_endpoint | * | |
| freebox* | hw_board | * | Only if `--status-sys` is used. |


## Metrics: connection (always)

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox | | config_adblock | |
| freebox | | config_wol | |
| freebox | | config_wol | |
| freebox | | config_ping_external | |
| freebox | | config_adblock | |
| freebox | | config_wol | |
| freebox | | config_sip_alg | |
| |
| freebox | remote_ip, remote_access_port | config_remote_is_secure_pass | |
| freebox | remote_ip, remote_access_port | config_remote_access | |
| freebox | remote_ip, remote_access_port | config_api_remote_access | |
| freebox | remote_ip, remote_access_port | config_api_allow_token_request | |

## Metrics: connection (FTTH, automatic)

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox | conn_media | bytes_down | |
| freebox | conn_media | bytes_up | |
| freebox | conn_media | rate_down | |
| freebox | conn_media | rate_up | |
| freebox | conn_media | bandwidth_down | |
| freebox | conn_media | bandwidth_up | |
| freebox | conn_media | state | |
| freebox | conn_media | wan_ipv4 | |
| freebox | conn_media | wan_ipv4_port_range_min | |
| freebox | conn_media | wan_ipv4_port_range_max | |
| freebox | conn_media | wan_ipv6 | |
| |
| freebox | conn_media, sfp_model, sfp_vendor, sfp_serial | sfp_pwr_rx | |
| freebox | conn_media, sfp_model, sfp_vendor, sfp_serial | sfp_pwr_tx | |
| freebox | conn_media, sfp_model, sfp_vendor, sfp_serial | sfp_alim_ok | |
| freebox | conn_media, sfp_model, sfp_vendor, sfp_serial | sfp_has_power_report | |
| freebox | conn_media, sfp_model, sfp_vendor, sfp_serial | sfp_has_signal | |


## Metrics: connection (xDSL, automatic)

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_status | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_modulation | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_uptime | |
| |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_es | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_attn | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_snr | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_rate | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_hec | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_crc | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_ses | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_fec | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_maxrate | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_rtx_tx | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_rtx_c | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_up_rtx_uc | |
| |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_es | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_attn | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_snr | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_rate | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_hec | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_crc | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_ses | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_fec | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_maxrate | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_rtx_tx | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_rtx_c | |
| freebox | conn_media, xdsl_status, xdsl_modulation, xdsl_protocol | xdsl_down_rtx_uc | |


## Metrics: parameter status-sys

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | sys_uptime | |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | sys_authenticated | |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | firmware_version | |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | sys_disk_status | |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | minfo_customer_hdd_slots | |
| freebox | hw_firmware, hw_serial, hw_mac, hw_model_pretty, hw_model, net_operator | minfo_internal_hdd_size | |
| |
| freebox | fan, fan_name | sys_fan_rpm | v8+ api only |
| freebox | sensor, sensor_name | sys_temp | v8+ api only<br/>sensor_name will specify either switch, CPU A, CPU B |
| freebox | | sys_fan_count | v8+ api only |
| freebox | | sys_temp_count | v8+ api only |
| freebox | sensor=main, sensor_name=main | sys_fan_rpm | older api only |
| freebox | sensor=main, sensor_name=main | sys_temp_sw | older api only |
| freebox | sensor=main, sensor_name=main | sys_temp_cpub | older api only |
| freebox | sensor=main, sensor_name=main | sys_temp_cpum | older api only |


## Metrics: parameter status-call

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_call | phone_number | call_phone_number | |
| |
| freebox_call | call, call_number, call_name, call_type, call_line_id, call_contact_id | call_duration | |
| freebox_call | call, call_number, call_name, call_type, call_line_id, call_contact_id | call_datetime | |
| freebox_call | call, call_number, call_name, call_type, call_line_id, call_contact_id | call_contact_id | |


## Metrics: parameter status-dhcp

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_dhcp | dhcp_gateway, dhcp_ip_range_start, dhcp_ip_range_end, dhcp_netmask, dhcp_dns | dhcp_enabled | |
| freebox_dhcp | dhcp_gateway, dhcp_ip_range_start, dhcp_ip_range_end, dhcp_netmask, dhcp_dns | dhcp_sticky_assign | |
| freebox_dhcp | dhcp_gateway, dhcp_ip_range_start, dhcp_ip_range_end, dhcp_netmask, dhcp_dns | dhcp_always_broadcast | |
| |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_static | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_refresh_time | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_assign_time | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_remaining_time | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_active | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_reachable | |
| freebox_dhcp | client_mac, client_hostname, client_ip, client_primary_name | dhcp_lease_last_time_reachable | |
| |
| freebox_dhcp | | dhcp_lease_count | |


## Metrics: parameter status-disk

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_storage | hdd, hdd_type, hdd_model, hdd_serial, hdd_table_type | disk_temp | |
| freebox_storage | hdd, hdd_type, hdd_model, hdd_serial, hdd_table_type | disk_total_bytes | |
| freebox_storage | hdd, hdd_type, hdd_model, hdd_serial, hdd_table_type | disk_idle | |
| freebox_storage | hdd, hdd_type, hdd_model, hdd_serial, hdd_table_type | disk_state | |
| freebox_storage | hdd, hdd_type, hdd_model, hdd_serial, hdd_table_type | disk_write_error | |
| |
| freebox_storage | hdd, hdd_type, partition, partition_label, partition_fstype, partition_state, partition_path | diskfs_total_bytes | |
| freebox_storage | hdd, hdd_type, partition, partition_label, partition_fstype, partition_state, partition_path | diskfs_used_bytes | |
| freebox_storage | hdd, hdd_type, partition, partition_label, partition_fstype, partition_state, partition_path | diskfs_free_bytes | |


## Metrics: parameter status-lan-browser

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_lan | lan_iface | lanhost_count | |
| |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_reachable | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_first_activity | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_last_activity | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_last_time_reachable | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_persistent | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_ipv4_active | |
| freebox_lan | lan_ipv4, lan_ipv6, lan_type, lan_primary_name, lan_vendor, lan_mac_address, lan_iface | lanhost_ipv6_active | |


## Metrics: parameter status-lte

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox | conn_media | lte_enabled | |
| freebox | conn_media | lte_state | |
| |
| freebox | conn_media, lte_net_ipv4, lte_net_ipv6 | lte_net_pdn_up | |
| |
| freebox | conn_media, lte_radio_gcid | lte_radio_associated | |
| freebox | conn_media, lte_radio_gcid | lte_radio_plmn | |
| freebox | conn_media, lte_radio_gcid | lte_radio_signal_level | |
| freebox | conn_media, lte_radio_gcid | lte_radio_ue_active | |
| |
| freebox | conn_media, band | lte_rband_enabled | |
| freebox | conn_media, band | lte_rband_bandwidth | |
| freebox | conn_media, band | lte_rband_pci | |
| freebox | conn_media, band | lte_rband_rsrp | |
| freebox | conn_media, band | lte_rband_rsrq | |
| freebox | conn_media, band | lte_rband_rssi | |
| |
| freebox | conn_media, sim_iccid | lte_sim | |
| freebox | conn_media, sim_iccid | lte_sim_pin_locked | |
| freebox | conn_media, sim_iccid | lte_sim_pin_remaining | |
| freebox | conn_media, sim_iccid | lte_sim_puk_locked | |
| freebox | conn_media, sim_iccid | lte_sim_puk_remaining | |


## Metrics: parameter status-switch

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_switch | | switch_port_count | |
| |
| freebox_switch | switch_port, switch_mode, switch_name | switch_link | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_duplex | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_speed | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_rx_bytes_rate | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_tx_bytes_rate | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_err_packets | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_discard_packets | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_collisions | |
| freebox_switch | switch_port, switch_mode, switch_name | switch_client_count | |
| |
| freebox_switch | switch_port, mac, hostname | client_last_seen | |

Notice: `switch_name` appeared with api v14 and is optional, it could be missing.


## Metrics: parameter status-virtualmachines

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_virtualmachine | | total_memory | |
| freebox_virtualmachine | | used_memory | |
| freebox_virtualmachine | | total_cpus | |
| freebox_virtualmachine | | usb_ports_count | |
| freebox_virtualmachine | | usb_used | |
| |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_status | |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_memory | |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_vcpus | |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_enable_screen | |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_bind_usb_ports_count | |
| freebox_virtualmachine | vm, vm_name, vm_disk_path, vm_disk_type, vm_cd_path, vm_cloudinit_hostname, vm_mac, vm_os | vm_enable_cloudinit | |


## Metrics: parameter status-vpnsrv

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_vpn_server | vpn_type, vpn_name, vpn_port, vpn_ip_start, vpn_ip_end, vpn_ip6_start, vpn_ip6_end | vpnsrv_state | |
| freebox_vpn_server | vpn_type, vpn_name, vpn_port, vpn_ip_start, vpn_ip_end, vpn_ip6_start, vpn_ip6_end | vpnsrv_connection_count | |
| freebox_vpn_server | vpn_type, vpn_name, vpn_port, vpn_ip_start, vpn_ip_end, vpn_ip6_start, vpn_ip6_end | vpnsrv_auth_connection_count | |
| freebox_vpn_server | vpn_type, vpn_name, vpn_port, vpn_ip_start, vpn_ip_end, vpn_ip6_start, vpn_ip6_end | vpnsrv_enabled | |


## Metrics: parameter status-vpnclient

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_vpn_client | ivc, ivc_type, ivc_description, ivc_username, ivc_remote_host, ivc_mtu, ivc_remote_host, ivc_remote_port | vpnclient_state | |
| |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_enabled | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_state | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_last_try | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_last_up | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_next_try | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_rate_up | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_rate_down | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_bytes_up | |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider | vpnconn_bytes_down | |
| |
| freebox_vpn_client | type, active_vpn_description, active_vpn, ipv4, ipv4_mask, ipv4_gateway, ipv4_domain, ipv4_provider, last_error_desc | vpnconn_last_error | |


## Metrics: parameter status-wifi

| Measurements | tags | metrics | comments |
| - | - | - | - |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_ap_band | wifi_state | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_ap_band | wifi_channel_width | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_ap_band | wifi_primary_channel | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_ap_band | wifi_secondary_channel | |
| |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_station_hostname, wifi_station_mac, wifi_station, wifi_station_bssid | wifi_station_tx_bytes | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_station_hostname, wifi_station_mac, wifi_station, wifi_station_bssid | wifi_station_rx_bytes | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_station_hostname, wifi_station_mac, wifi_station, wifi_station_bssid | wifi_station_signal | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_station_hostname, wifi_station_mac, wifi_station, wifi_station_bssid | wifi_station_conn_duration | |
| freebox_wifi | wifi_ap, wifi_ap_name, wifi_station_hostname, wifi_station_mac, wifi_station, wifi_station_bssid | wifi_station_inactive | |
