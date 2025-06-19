#!/usr/bin/env python
# pylint: disable=C0103,C0111,W0621
from __future__ import print_function

import requests
import os
import json
import hmac
import time
import argparse
import sys
from hashlib import sha1

import socket

if sys.version_info >= (3, 0):
    import configparser as configp
else:
    import ConfigParser as configp

#
# Freebox API SDK
# Home: https://dev.freebox.fr/sdk/server.html
# Doc1: http://dev.freebox.fr/sdk/
# Doc2: http://mafreebox.freebox.fr/#Fbx.os.app.help.app
#

APP_VERSION = "0.6.0"
APP_ID = "fr.freebox.seximonitor"
APP_NAME = "SexiMonitor"


# variables & constants -----------------------------------
DEBUG = 0  # updated by the cmdline
SSL_VERIFY = 1     # updated by the cmdline

ENDPOINT_HOST = "mafreebox.freebox.fr"
ENDPOINT_FAILSAFE = "http://mafreebox.freebox.fr/api/v4"


# updated on the first API connection
ENDPOINT = ""
ENDPOINT_SSL = 0

# extra tags in the response - updated when retrieving system data
OUTPUT_TAGS = {"hw_operator": "Free"}


def debug_output(sData):
    if not DEBUG:
        return
    print("%s" % sData)


def get_api_endpoint_detect():
    global ENDPOINT
    global ENDPOINT_SSL

    api_endpoint_detect_url = 'http://%s/api_version' % (ENDPOINT_HOST)
    r = requests.get(api_endpoint_detect_url)

    if r.status_code != 200:
        print("Failed request: %s\n" % r.text)
        sys.exit(1)

    json_raw = r.json()

    # extract the endpoint informations
    # TODO: see if using "json_raw['api_domain'] + json_raw['https_port']" instead of "mafreebox..." is a good idea
    api_endpoint_url = "http://%s:80" % (ENDPOINT_HOST)
    if bool(json_raw['https_available']):
        api_endpoint_url = "https://%s:%s" % (ENDPOINT_HOST, str(443) )
        ENDPOINT_SSL = 1

    # extract the api base path and remove the leading and ending /
    api_endpoint_path = str(json_raw['api_base_url']).strip()
    if api_endpoint_path.startswith('/'):
        api_endpoint_path = api_endpoint_path[1:]

    if api_endpoint_path.endswith('/'):
        api_endpoint_path = api_endpoint_path[:-1]        

    # extract the api major version
    api_endpoint_version_major = int( float(json_raw['api_version']) )

    # endpoint final url
    ENDPOINT = "%s/%s/v%s" % (api_endpoint_url, api_endpoint_path, str(api_endpoint_version_major))
    debug_output("get_api_endpoint_detect() => endpoint detected: %s" % ENDPOINT)
    set_api_ssl_verification()


def set_api_ssl_verification():
    debug_output("set_api_ssl_verification() => ssl status: %s (check validity: %d)" % (ENDPOINT_SSL, SSL_VERIFY) )
    if ENDPOINT_SSL and not SSL_VERIFY:
        # Disable SSL verification
        # TODO: manage the self-signed free telecom CA
        os.environ['REQUESTS_CA_BUNDLE'] = ''                       # no effect after requests v2.28.0
        requests.packages.urllib3.disable_warnings()                # disable warnings messages


def get_challenge(freebox_track_id):
    api_url = '%s/login/authorize/%s' % (ENDPOINT, freebox_track_id)
    debug_output("get_challenge() => url: %s" % api_url)

    # change the number of retries - there is no "request.max_retries = x"
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)

    r = http.get(api_url, verify=SSL_VERIFY)
    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def open_session(password, freebox_app_id):
    api_url = '%s/login/session/' % ENDPOINT
    debug_output("open_session() => url: %s" % api_url)

    app_info = {
        'app_id': freebox_app_id,
        'password': password
    }
    json_payload = json.dumps(app_info)

    r = requests.post(api_url, data=json_payload, verify=SSL_VERIFY)

    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def get_request_api_url(sApiUrl, oHeaders, nStatusCode_success = 200):
    debug_output("get_request_api_url() => url: %s" % sApiUrl)

    r = requests.get(sApiUrl, headers=oHeaders, verify=SSL_VERIFY)
    if r.status_code == nStatusCode_success:
        debug_output( json.dumps(r.json(), indent=4, sort_keys=True) )
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)
    

def get_internal_disk_stats(headers):
    api_url = '%s/storage/disk/1' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_connection_stats(headers):
    api_url = '%s/connection/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_dhcp_config(headers):
    api_url = '%s/dhcp/config/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_dhcp_dynamic(headers):
    api_url = '%s/dhcp/dynamic_lease/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_dhcp_static(headers):
    api_url = '%s/dhcp/static_lease/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_ftth_status(headers):
    api_url = '%s/connection/ftth/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_lteconfig_status(headers):
    api_url = '%s/connection/lte/config' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_system_config(headers):
    api_url = '%s/system/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_system_model(headers):
    # the model is on the /api_version path
    api_url = 'http://%s/api_version' % (ENDPOINT_HOST)
    r = requests.get(api_url)
    debug_output( json.dumps(r.json(), indent=4, sort_keys=True) )
    return r.json()


def get_switch_status(headers):
    api_url = '%s/switch/status/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_switch_port_stats(headers, port):
    api_url = '%s/switch/port/%s/stats' % (ENDPOINT, port)
    return get_request_api_url(api_url, headers)


def get_wifi_stats(headers):
    api_url = '%s/wifi/ap/' % (ENDPOINT)
    return get_request_api_url(api_url, headers)


def get_wifi_stats_station(headers, num):
    api_url = '%s/wifi/ap/%s/stations' % (ENDPOINT, num)
    return get_request_api_url(api_url, headers)


def get_xdsl_status(headers):
    api_url = '%s/connection/xdsl/' % ENDPOINT
    return get_request_api_url(api_url, headers)


def get_and_print_metrics(creds, sOutputFormat, s_sys = 0, s_switch = 0, s_ports = 1, s_disk = 0):
    global OUTPUT_TAGS

    # Fetch challenge
    resp = get_challenge(creds['track_id'])
    challenge = resp['result']['challenge']

    # Generate session password
    if sys.version_info >= (3, 0):
        h = hmac.new(bytearray(creds['app_token'], 'ASCII'), bytearray(challenge, 'ASCII'), sha1)
    else:
        h = hmac.new(creds['app_token'], challenge, sha1)
    password = h.hexdigest()

    # Fetch session_token
    resp = open_session(password, APP_ID)
    session_token = resp['result']['session_token']

    # Setup headers with the generated session_token
    headers = {
        'X-Fbx-App-Auth': session_token
    }

    # Setup hashtable for results
    my_data = {}

    # Fetch connection stats
    json_raw = get_connection_stats(headers)

    # Generic datas, same for FFTH or xDSL
    if 'result' in json_raw:
        my_data['bytes_down'] = json_raw['result']['bytes_down']  # total in bytes since last connection
        my_data['bytes_up'] = json_raw['result']['bytes_up']

        my_data['rate_down'] = json_raw['result']['rate_down']  # current rate in byte/s
        my_data['rate_up'] = json_raw['result']['rate_up']

        my_data['bandwidth_down'] = json_raw['result']['bandwidth_down']  # available bw in bit/s
        my_data['bandwidth_up'] = json_raw['result']['bandwidth_up']

    if json_raw['result']['state'] == "up":
        my_data['state'] = 1
        if 'ipv4' in json_raw['result']:
            my_data['wan_ipv4'] = json_raw['result']['ipv4']
            my_data['wan_ipv4_port_range_min'] = json_raw['result']['ipv4_port_range'][0]
            my_data['wan_ipv4_port_range_max'] = json_raw['result']['ipv4_port_range'][1]

        if 'ipv6' in json_raw['result']:
            my_data['wan_ipv6'] = json_raw['result']['ipv6']

    else:
        my_data['state'] = 0


    # ffth for FFTH (default)
    # xdsl for xDSL
    connection_media = json_raw['result'].get('media', 'none')

    ###
    # FFTH specific
    if connection_media in ["ffth", "ftth"]:
        json_raw = get_ftth_status(headers)
        if 'result' in json_raw:
            my_data['sfp_pwr_rx'] = json_raw['result']['sfp_pwr_rx']  # scaled by 100 (in dBm)
            my_data['sfp_pwr_tx'] = json_raw['result']['sfp_pwr_tx']
            my_data['sfp_alim_ok'] = 1 if json_raw['result']['sfp_alim_ok'] else 0
            my_data['sfp_has_power_report'] = 1 if json_raw['result']['sfp_has_power_report'] else 0
            my_data['sfp_has_signal'] = 1 if json_raw['result']['sfp_has_signal'] else 0

    ###
    # xDSL specific
    if connection_media == "xdsl":
        json_raw = get_xdsl_status(headers)
        if 'result' in json_raw:
            my_data['xdsl_modulation'] = json_raw['result']['status']['modulation'] + " (" + json_raw['result']['status']['protocol'] + ")"
            my_data['xdsl_uptime'] = json_raw['result']['status']['uptime']  # in seconds
            my_data['xdsl_status_string'] = json_raw['result']['status']['status']

            if json_raw['result']['status']['status'] == "down":  # unsynchronized
                my_data['xdsl_status'] = 0
            elif json_raw['result']['status']['status'] == "training":  # synchronizing step 1/4
                my_data['xdsl_status'] = 1
            elif json_raw['result']['status']['status'] == "started":  # synchronizing step 2/4
                my_data['xdsl_status'] = 2
            elif json_raw['result']['status']['status'] == "chan_analysis":  # synchronizing step 3/4
                my_data['xdsl_status'] = 3
            elif json_raw['result']['status']['status'] == "msg_exchange":  # synchronizing step 4/4
                my_data['xdsl_status'] = 4
            elif json_raw['result']['status']['status'] == "showtime":  # ready
                my_data['xdsl_status'] = 5
            elif json_raw['result']['status']['status'] == "disabled":  # disabled
                my_data['xdsl_status'] = 6
            else:  # unknown
                my_data['xdsl_status'] = 999

            for sDir in ['down', 'up']:
                my_data['xdsl_%s_es' % sDir] =   json_raw['result'][sDir]['es']   # increment
                my_data['xdsl_%s_attn' % sDir] = json_raw['result'][sDir]['attn'] # in dB
                my_data['xdsl_%s_snr' % sDir] =  json_raw['result'][sDir]['snr']  # in dB
                my_data['xdsl_%s_rate' % sDir] = json_raw['result'][sDir]['rate'] # ATM rate in kbit/s
                my_data['xdsl_%s_hec' % sDir] =  json_raw['result'][sDir]['hec']  # increment
                my_data['xdsl_%s_crc' % sDir] =  json_raw['result'][sDir]['crc']  # increment
                my_data['xdsl_%s_ses' % sDir] =  json_raw['result'][sDir]['ses']  # increment
                my_data['xdsl_%s_fec' % sDir] =  json_raw['result'][sDir]['fec']  # increment
                my_data['xdsl_%s_maxrate' % sDir] = json_raw['result'][sDir]['maxrate']  # ATM max rate in kbit/s

                # older api compatibility
                if 'rtx_tx' in json_raw['result'][sDir]:
                    my_data['xdsl_%s_rtx_tx' % sDir] = json_raw['result'][sDir]['rtx_tx']      # G.INP on/off
                    my_data['xdsl_%s_rtx_c' % sDir] =  json_raw['result'][sDir]['rtx_c']       # G.INP corrected
                    my_data['xdsl_%s_rtx_uc' % sDir] = json_raw['result'][sDir]['rtx_uc']      # G.INP uncorrected
                else:
                    my_data['xdsl_%s_rtx_tx' % sDir] = json_raw['result'][sDir]['rxmt']        # G.INP on/off
                    my_data['xdsl_%s_rtx_c' % sDir] =  json_raw['result'][sDir]['rxmt_corr']   # G.INP corrected
                    my_data['xdsl_%s_rtx_uc' % sDir] = json_raw['result'][sDir]['rxmt_uncorr'] # G.INP uncorrected


    ##
    # General infos
    if s_sys:
        sys_json_raw = get_system_config(headers)
        if 'result' in sys_json_raw:
            my_data['sys_fan_rpm'] = sys_json_raw['result']['fan_rpm'] # rpm
            my_data['sys_temp_sw'] = sys_json_raw['result']['temp_sw']  # Temp Switch, degree Celcius
            my_data['sys_uptime'] = sys_json_raw['result'].get('uptime_val', 0) # Uptime, in seconds
            my_data['sys_temp_cpub'] = sys_json_raw['result']['temp_cpub']  # Temp CPU Broadcom, degree Celcius
            my_data['sys_temp_cpum'] = sys_json_raw['result']['temp_cpum']  # Temp CPU Marvell, degree Celcius
            my_data['firmware_version'] = sys_json_raw['result']['firmware_version']  # Firmware version
            my_data['sys_authenticated'] = sys_json_raw['result']['box_authenticated']  # box at step 6

            OUTPUT_TAGS["hw_board"] = sys_json_raw['result']['board_name']
            OUTPUT_TAGS["hw_serial"] = sys_json_raw['result']['serial']

        sysmodel_json_raw = get_system_model(headers)
        # no result sublevel for _system_model
        OUTPUT_TAGS["hw_model"] = sysmodel_json_raw['box_model']


    ##
    # Switch status
    if s_switch:
        switch_json_raw = get_switch_status(headers)
        if 'result' in switch_json_raw:
            nSwitchPortCount = 0

            for i in switch_json_raw['result']:
                # 0 down, 1 up
                my_data['switch_%s_link' % i['id']] = 1 if i['link'].lower() == "up" else 0
                # 0 half, 1 full
                my_data['switch_%s_duplex' % i['id']] = 1 if i['duplex'].lower() == "full" else 0
                my_data['switch_%s_speed' % i['id']] = int( i['speed'] )
                nSwitchPortCount = nSwitchPortCount + 1

            ##
            # Switch ports status
            if s_ports:
                for i in range(1, nSwitchPortCount + 1 ):
                    switch_port_stats = get_switch_port_stats(headers, i)
                    if 'result' in switch_port_stats:
                        # these metrics exist for both "rx_*" and "tx_*"
                        for sMode in ['rx', 'tx']:
                            my_data['switch_%s_%s_bytes_rate' % (i, sMode)] = switch_port_stats['result']['%s_bytes_rate' % sMode]  # bytes/s

                        # these metrics only exist on one mode
                        my_data['switch_%s_err_packets' % i] = switch_port_stats['result']['rx_err_packets']
                        my_data['switch_%s_discard_packets' % i] = switch_port_stats['result']['rx_discard_packets']
                        my_data['switch_%s_collisions' % i] = switch_port_stats['result']['tx_collisions']


    # Fetch internal disk stats
    if s_disk:
        json_raw = get_internal_disk_stats(headers)
        if 'result' in json_raw and 'partitions' in json_raw['result']:
            if 'total_bytes' in json_raw['result']['partitions'][0]:
                my_data['disk_total_bytes'] =  json_raw['result']['partitions'][0]['total_bytes']
            if 'used_bytes'  in json_raw['result']['partitions'][0]:
                my_data['disk_used_bytes'] =  json_raw['result']['partitions'][0]['used_bytes']
            if 'temp' in json_raw['result']:
                my_data['disk_temp'] =  json_raw['result']['temp']


    # Switching between outputs formats 
    if sOutputFormat == 'influxdb':
        # Prepping Influxdb Data format
        timestamp = int(time.time())* 1000000

        # generate the tag list
        sOutputTags=""
        for x, y in OUTPUT_TAGS.items():
            sOutputTags = sOutputTags + ',' + x + "=\"" + y + "\""

        # Output the information - format is : measurement,tag=name,tag=name metric=value,metric=value time
        for i in my_data:
            if type(my_data[i]) == str:
                my_data[i] = "\"" + my_data[i] + "\""
            print("freebox%s %s=%s %d" % (sOutputTags, i, my_data[i], timestamp))

    else:
        # Prepping Graphite Data format
        timestamp = int(time.time())

        # generate the tag list
        sOutputTags=""
        for x, y in OUTPUT_TAGS.items():
            sOutputTags = sOutputTags + ';' + x + "=\"" + y + "\""

        # Output the information - format is : measurement.metric;tag=name;tag=name value time
        for i in my_data:
            print("freebox.%s%s %s %d" % (i, sOutputTags, my_data[i], timestamp))


def get_auth():
    global ENDPOINT
    global ENDPOINT_SSL
    
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cfg_file = os.path.join(script_dir, ".credentials")

    f = configp.RawConfigParser()
    f.read(cfg_file)

    try:
        _ = f.get("general", "track_id")
        _ = f.get("general", "app_token")
    except configp.NoSectionError:
        print("Config is invalid, the auth token is missing.")
        return None

    # set the global variables
    ENDPOINT = f.get('general', 'api_endpoint', fallback=ENDPOINT_FAILSAFE)
    ENDPOINT_SSL = int( f.get('general', 'api_ssl', fallback=ENDPOINT_SSL) )

    return {'track_id': f.get('general', 'track_id'),
            'app_token': f.get('general', 'app_token'),
            'api_endpoint': ENDPOINT,
            'api_ssl': ENDPOINT_SSL,
            }


def write_auth(auth_infos):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cfg_file = os.path.join(script_dir, ".credentials")
    f = configp.RawConfigParser()
    f.add_section("general")
    f.set("general", "track_id", auth_infos['track_id'])
    f.set("general", "app_token", auth_infos["app_token"])
    f.set("general", "api_endpoint", ENDPOINT)
    f.set("general", "api_ssl", str(ENDPOINT_SSL) )

    with open(cfg_file, "wb") as authFile:
        f.write(authFile)


def do_register(creds):
    if creds is not None:
        if 'track_id' in creds and 'app_token' in creds:
            print("Already registered, exiting")
            return

    print("Doing registration")
    headers = {'Content-type': 'application/json'}
    app_info = {
        'app_id': APP_ID,
        'app_name': APP_NAME,
        'app_version': APP_VERSION,
        'device_name': socket.gethostname()
    }
    json_payload = json.dumps(app_info)

    r = requests.post('%s/login/authorize/' % ENDPOINT, headers=headers, data=json_payload, verify=SSL_VERIFY)
    register_infos = None

    if r.status_code == 200:
        register_infos = r.json()
    else:
        print('Failed registration: %s\n' % r.text)

    write_auth(register_infos['result'])
    print("Don't forget to accept the authentication on the Freebox panel !")


def register_status(creds):
    if not creds:
        print("Status: invalid config, auth is missing.")
        print("Please run `%s --register` to register app." % sys.argv[0])
        return

    print("Status:")
    print("  track_id: %s" % creds["track_id"])
    print("  app_token: %s" % creds["app_token"])
    print("  api_endpoint: %s" % creds["api_endpoint"])
    print("  api_ssl: %s" % creds["api_ssl"])


# Main
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--register', action='store_true', help="Register app with Freebox API and cache the API endpoint URL")
    parser.add_argument('-s', '--register-status', dest='status', action='store_true', help="Get register status")
    parser.add_argument('-f', '--format', dest='format', choices=['graphite', 'influxdb'], default='graphite', help="Specify output format between 'graphite' and 'influxdb'")
    parser.add_argument('-e', '--api-endpoint-detect-force', dest='endpoint_detect_force', action='store_true', help="Force the detection of the api endpoint on each access")
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Activate the debug mode and print the retrieved data")
    parser.add_argument('--ssl-no-verify', dest='ssl_verify', action='store_false', help="Disable the certificate validity tests on ssl connections")

    parser.add_argument('-S', '--status-switch',
                        dest='status_switch',
                        action='store_true',
                        help="Get and show switch status")

    parser.add_argument('-P', '--status-ports',
                        dest='status_ports',
                        action='store_true',
                        help="Obsolete - integrated into --status-switch and kept for compatibility")

    parser.add_argument('-H', '--status-sys',
                        dest='status_sys',
                        action='store_true',
                        help="Get and show system status")

    parser.add_argument('-D', '--internal-disk-usage',
                        dest='disk_usage',
                        action='store_true',
                        help="Get and show internal disk usage")


    args = parser.parse_args()

    DEBUG = args.debug
    SSL_VERIFY = args.ssl_verify

    auth = get_auth()
    set_api_ssl_verification()

    if args.register:
        get_api_endpoint_detect()
        do_register(auth)

    elif args.status:
        register_status(auth)

    else:
        if args.endpoint_detect_force:
            get_api_endpoint_detect()

        get_and_print_metrics(auth, sOutputFormat = args.format.lower(),
                s_sys = args.status_sys,
                s_switch = args.status_switch,
                s_disk = args.disk_usage)
