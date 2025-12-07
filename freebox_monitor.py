#!/usr/bin/env python
# coding: latin-1  # pylint: disable=C0103,C0111,C2503,W0621
from __future__ import print_function

import os
import json
import hmac
import time
import argparse
import sys
import hashlib
import base64
import re
import socket
import requests

# configparser python compatibility
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

APP_ID = "fr.freebox.seximonitor"
APP_NAME = "SexiMonitor"

APP_VERSION = "0.9.0"

# max api and firmware tested upon
# bugs : SSL is not supported if the box has no WAN connection - might be related to using an external domain, but the box itself can still do ssl
# bugs : API v7 mix rate_up and bytes_up with rate_down/bytes_down => task #40445
APP_TESTED_MAX_API = "15"
APP_TESTED_MAX_FIRMWARE = "4.9.13"

# variables & constants -----------------------------------
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join( SCRIPT_DIR, ".credentials")


ENDPOINT_HOST = "mafreebox.freebox.fr"
ENDPOINT_PORT = 80
ENDPOINT_SSL = 0

ENDPOINT_FAILSAFE = "http://mafreebox.freebox.fr/api/v4"
ENDPOINT_REQUEST_TIMEOUT = 5
ENDPOINT_AUTH_HASH = "sha1"

# Separators depending of the output type
# influxdb has no real notion of a submeasure, so a concatenation will be done instead
OUTPUT_MEASUREMENT = {
    "influxdb": {"measure_separator": "_", "tag_separator": ","},
    "graphite": {"measure_separator": ".", "tag_separator": ";"},
    "name": "freebox"
}

# updated on the first API connection
ENDPOINT = ""
ENDPOINT_API_MAJOR_FORCE = 0

# updated by the cmdline
DEBUG = 0
SSL_VERIFY = 1
SSL_CUSTOM_CA_BUNDLE_FILE = os.path.join( SCRIPT_DIR, "ssl/free_telecom_bundle.pem")
PATCH_FIX_RATE_UP_BYTES_UP = 0         # specific for having rate_up & bytes_up cumuled with rate_down &  bytes_down

DATA_CONNECTION_STATS_MEDIA = ""

# extra tags in the response - updated on the connection with the endpoint URL and when retrieving the system metrics
OUTPUT_TAGS_GLOBAL = {}

# Setup hashtable for results
# all insertion must be attached to an unique name with the following structure :
# OUTPUT_DATA_FINAL['UID'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}
# - "UID" is a random unique name
# - "measure" can be empty, it will defaut to "freebox" (defined with OUTPUT_MEASUREMENT[name]), otherwise it will be "freebox_<measure_name>"
# - "tags" is a list of tags to apply to the data, with the format : { "tag_A": "value A", "tag_B": "value B", ...}
# - "data" is a list of metris with their values, with the format : { "metric_X": "value X", "metric_Y": 421, ...}
# - Spaces are supported only for tags values.
#
OUTPUT_DATA_FINAL = {}

###############################################################################
# Functions


# debug output to stdout ------------------------------------------------------
def debug_output(sData):
    if not DEBUG:
        return
    # TODO: add time
    print("DEBUG: %s" % sData)


# replace accents and special chars with their ascii counterpart --------------
def replace_accents_string(sText):
    # ref: https://coderivers.org/blog/python-replace-accented-character-with-ascii-character/
    replacements = {
        r'à|á|â|ã|ä|å': 'a',
        r'è|é|ê|ë': 'e',
        r'ì|í|î|ï': 'i',
        r'ò|ó|ô|õ|ö': 'o',
        r'ù|ú|û|ü': 'u',
        r'ý|ÿ': 'y',
        r'ç': 'c',
        r'\\': '/',
        r'\.|:|,|;|\\|"|\'': ' ',
        r'  +': ' '
    }
    for pattern, replacement in replacements.items():
        sText = re.sub(pattern, replacement, sText, flags=re.IGNORECASE)
    return sText.strip()


# replace by a space any ".;()[]/\" from a string -----------------------------
def sanitize_string(sText):
    return re.sub( '[' + re.escape('.;()[]/\\') + ']+', ' ', str(sText), flags=re.IGNORECASE).strip()


# retrieve the api informations to generate the api endpoint url --------------
def get_api_endpoint_detect(bApiEndpointDetectDomainSsl):
    global ENDPOINT, ENDPOINT_HOST, ENDPOINT_PORT, ENDPOINT_SSL

    sEndpointDomain = "http://%s:%s" % (ENDPOINT_HOST, str(ENDPOINT_PORT) )

    api_endpoint_detect_url = '%s/api_version' % (sEndpointDomain)
    debug_output("get_api_endpoint_detect() => url: %s" % api_endpoint_detect_url)

    r = requests.get(api_endpoint_detect_url, timeout=ENDPOINT_REQUEST_TIMEOUT)
    if r.status_code != 200:
        print("Failed api endpoint detection : %s\n" % r.text)
        sys.exit(1)

    json_raw = r.json()
    debug_output( json.dumps(json_raw, indent=4, sort_keys=True) )

    # extract the endpoint informations for ssl usage and update sEndpointDomain
    # TODO: usage of "uid" in the response ?
    if 'https_available' in json_raw and bool(json_raw['https_available']):
        # default values
        ENDPOINT_PORT = 443
        ENDPOINT_SSL = 1

        debug_output("get_api_endpoint_detect() => autoconfiguration for the SSL domain & port is : %s" % str(bApiEndpointDetectDomainSsl) )
        if bApiEndpointDetectDomainSsl:
            if 'api_domain' in json_raw and len(json_raw['api_domain']) > 0:
                ENDPOINT_HOST = json_raw['api_domain'].strip()

            if 'https_port' in json_raw and json_raw['https_port'] > 0:
                ENDPOINT_PORT = json_raw['https_port']

        sEndpointDomain = "https://%s:%s" % (ENDPOINT_HOST, str(ENDPOINT_PORT) )

    # extract the api base path and remove the leading and ending /
    api_endpoint_path = str(json_raw['api_base_url']).strip()
    if api_endpoint_path.startswith('/'):
        api_endpoint_path = api_endpoint_path[1:]

    if api_endpoint_path.endswith('/'):
        api_endpoint_path = api_endpoint_path[:-1]

    # extract the api major version from the version float number (even "12" is returned as "12.0")
    api_endpoint_version_major = int( float(json_raw['api_version']) )
    if ENDPOINT_API_MAJOR_FORCE > 0:
        api_endpoint_version_major = ENDPOINT_API_MAJOR_FORCE
        debug_output("get_api_endpoint_detect() => API version forced to: %s" % ENDPOINT_API_MAJOR_FORCE)

    # endpoint final url
    ENDPOINT = "%s/%s/v%s" % (sEndpointDomain, api_endpoint_path, str(api_endpoint_version_major))
    debug_output("get_api_endpoint_detect() => final endpoint detected: %s" % ENDPOINT)
    set_api_ssl_verification()


# adjust the access to ignore or validate the api ssl certificate -------------
def set_api_ssl_verification():
    debug_output("set_api_ssl_verification() => use ssl = %s | cert verification = %s" % (ENDPOINT_SSL, str(SSL_VERIFY)) )
    if ENDPOINT_SSL:
        if SSL_VERIFY:
            debug_output("set_api_ssl_verification() => ssl bundle: %s" % SSL_CUSTOM_CA_BUNDLE_FILE)
            os.environ['REQUESTS_CA_BUNDLE'] = SSL_CUSTOM_CA_BUNDLE_FILE
            if not os.path.isfile(SSL_CUSTOM_CA_BUNDLE_FILE):
                print("\nError: the CA certificate file '%s' is missing or not accessible.\nYou can use the parameter '--ssl-no-verify' if you do not have a CA certificate.\n" % SSL_CUSTOM_CA_BUNDLE_FILE)    # pylint: disable=line-too-long # noqa C0301
                sys.exit(1)

        else:
            debug_output("set_api_ssl_verification() => disabling ssl cert verification was requested")
            # Disable SSL verification
            os.environ['REQUESTS_CA_BUNDLE'] = ''                       # no effect after requests v2.28.0
            requests.packages.urllib3.disable_warnings()                # disable warnings messages


# get the api login challenge -------------------------------------------------
# used by get_auth_header_for_session()
def get_challenge(freebox_track_id):
    api_url = '%s/login/authorize/%s' % (ENDPOINT, freebox_track_id)
    debug_output("get_challenge() => url: %s" % api_url)

    # change the number of retries - there is no "request.max_retries = x"
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)

    r = http.get(api_url, verify=SSL_VERIFY, timeout=ENDPOINT_REQUEST_TIMEOUT)
    if r.status_code != 200:
        print("Failed challenge request: %s\n" % r.text)
        sys.exit(2)

    return r.json()


# generate the session password from the token and the challenge string -------
# used by get_auth_header_for_session()
def do_challenge_session_password(sToken, sChallenge):
    debug_output("do_challenge_session_password() => token size: %d, hash type: %s" % (len(sToken), ENDPOINT_AUTH_HASH) )

    if sys.version_info >= (3, 0):
        h = hmac.new(bytearray(sToken, 'ASCII'), bytearray(sChallenge, 'ASCII'), ENDPOINT_AUTH_HASH)
    else:
        # python2 support
        h = hmac.new(sToken, sChallenge, hashlib.sha1)

    return h.hexdigest()


# open a session with the  app id and password --------------------------------
# used by get_auth_header_for_session()
def open_session(password, freebox_app_id):
    api_url = '%s/login/session/' % ENDPOINT
    debug_output("open_session() => url: %s" % api_url)

    app_info = {
        'app_id': freebox_app_id,
        'password': password
    }
    json_payload = json.dumps(app_info)

    r = requests.post(api_url, data=json_payload, verify=SSL_VERIFY, timeout=ENDPOINT_REQUEST_TIMEOUT)

    if r.status_code != 200:
        print("Failed session opening request: %s\n" % r.text)
        if "invalid_token" in r.text:
            print("In case of an invalid token error, please verify if the %s algorithm used for the challenge is supported by the endpoint when opening a session.\n" % ENDPOINT_AUTH_HASH)
        sys.exit(2)

    return r.json()


# open a session and generate the authent header ------------------------------
def get_auth_header_for_session(aCreds, sAppUid):
    # Fetch challenge
    aResp = get_challenge(aCreds['track_id'])
    password = do_challenge_session_password(aCreds['app_token'], aResp['result']['challenge'])

    # Fetch session_token
    aSession = open_session(password, sAppUid)
    sSessionToken = aSession['result']['session_token']

    # Setup headers with the generated token
    sHeaders = {
        'X-Fbx-App-Auth': sSessionToken
    }

    return sHeaders


# send a request to the api for an expected status code -----------------------*
# used by get_request_api_url_result()
def get_request_api_url(sApiUrl, oHeaders, nStatusCode_success = 200):
    debug_output("get_request_api_url() => url: %s" % sApiUrl)

    r = requests.get(sApiUrl, headers=oHeaders, verify=SSL_VERIFY, timeout=ENDPOINT_REQUEST_TIMEOUT)
    if r.status_code == nStatusCode_success:
        debug_output( json.dumps(r.json(), indent=4, sort_keys=True) )
        return r.json()

    print("get_request_api_url(): Failed API request (%s): %s\n" % (sApiUrl, r.text))
    return None


# wrapper for get_request_api_url() and returning the data under .get("result") or null
def get_request_api_url_result(sApiUrl, oHeaders, sDataSection = "result"):
    oJson = get_request_api_url(sApiUrl, oHeaders)
    try:
        return oJson.get(sDataSection, None)
    except:             # pylint: disable=bare-except  # noqa: E722
        return None


# Phone call logs ---------------------------------------------------------
def get_call_account(sHeaders):
    api_url = '%s/call/account/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "call"
    my_data = {}; my_tags = {}

    my_data['call_phone_number'] = json_raw['phone_number']

    # add it also as a tag
    my_tags['phone_number'] = json_raw['phone_number']

    OUTPUT_DATA_FINAL['call_phone_number'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Phone call logs : stats -------------------------------------------------
def get_call_stats(sHeaders):
    api_url = '%s/call/log/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "call"
    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['call_duration'] = i['duration']  # in secs
        my_data['call_datetime'] = i['datetime']  # unix timestamp
        my_data['call_contact_id'] = i['contact_id']

        my_tags['call'] = i['id']
        my_tags['call_number'] = i['number']
        my_tags['call_name'] = i['name']
        my_tags['call_type'] = i['type']
        my_tags['call_line_id'] = i['line_id']
        my_tags['call_contact_id'] = i['contact_id']  # also as a tag

        OUTPUT_DATA_FINAL['call_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Generic connection config ---------------------------------------------------
def get_connection_config(sHeaders):
    api_url = '%s/connection/config/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = ""
    my_data = {}; my_tags = {}

    my_data['config_ping_external'] = 1 if json_raw.get('ping', 0) else 0
    my_data['config_adblock'] = 1 if json_raw.get('adblock', 0) else 0
    my_data['config_wol'] = 1 if json_raw.get('wol', 0) else 0

    # convert the SIP ALG name to a number
    CONVERT_SIP_ALG = { "none": -1,
                        "disabled": 0,
                        "direct_media": 1,
                        "any_media": 2
                    }
    # TODO: also add "sip_alg" as a tag
    my_data['config_sip_alg'] = CONVERT_SIP_ALG.get( json_raw.get('sip_alg', "none"), 999)

    OUTPUT_DATA_FINAL['connection_config'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

    # special case for *remote_access
    my_data = {}; my_tags = {}

    my_data['config_remote_is_secure_pass'] = 1 if json_raw.get('is_secure_pass', 0) else 0
    my_data['config_remote_access'] = 1 if json_raw.get('remote_access', 0) else 0
    my_data['config_api_remote_access'] = 1 if json_raw.get('api_remote_access', 0) else 0
    my_data['config_api_allow_token_request'] = 1 if json_raw.get('allow_token_request', 0) else 0

    my_tags['remote_ip'] = json_raw.get('remote_access_ip', "none")
    my_tags['remote_access_port'] = json_raw.get('remote_access_port', 0)

    OUTPUT_DATA_FINAL['connection_config_remote'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Generic connection config : stats -------------------------------------------
def get_connection_stats(sHeaders):
    global DATA_CONNECTION_STATS_MEDIA, PATCH_FIX_RATE_UP_BYTES_UP

    api_url = '%s/connection/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = ""
    my_data = {}; my_tags = {}

    # bug : rate_up & bytes_up are cumulated with their *_down counterpart
    # the PATCH_FIX_RATE_UP_BYTES_UP fix for anormal data is managed in the switch metrics function

    my_data['bytes_down'] = json_raw['bytes_down']  # total in bytes since last connection
    my_data['bytes_up'] = json_raw['bytes_up']

    my_data['rate_down'] = json_raw['rate_down']  # current rate in byte/s
    my_data['rate_up'] = json_raw['rate_up']

    my_data['bandwidth_down'] = json_raw['bandwidth_down']  # available bandwidth in bit/s
    my_data['bandwidth_up'] = json_raw['bandwidth_up']

    DATA_CONNECTION_STATS_MEDIA = json_raw.get('media', 'none').lower()

    if json_raw['state'] == "up":
        my_data['state'] = 1
        if 'ipv4' in json_raw:
            my_data['wan_ipv4'] = json_raw['ipv4']
            my_data['wan_ipv4_port_range_min'] = json_raw['ipv4_port_range'][0]
            my_data['wan_ipv4_port_range_max'] = json_raw['ipv4_port_range'][1]
            my_data['wan_ipv6'] = json_raw['ipv6'] if 'ipv6' in json_raw else 'none'

    else:
        # when using ffth and the connection is down, "media" will switch to xdsl without warning
        DATA_CONNECTION_STATS_MEDIA = "down"
        my_data['state'] = 0
        my_data['wan_ipv4'] = "none"
        my_data['wan_ipv4_port_range_min'] = 0
        my_data['wan_ipv4_port_range_max'] = 0
        my_data['wan_ipv6'] = "none"

        # disable fix rate/bytes_up if the connection is down to prevent sending wrong data
        PATCH_FIX_RATE_UP_BYTES_UP = 0

    my_tags['conn_media'] = DATA_CONNECTION_STATS_MEDIA
    OUTPUT_DATA_FINAL['connection'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# FFTH specific -----------------------------------------------------------
def get_conn_ftth_status(sHeaders, sConnectionMedia):
    api_url = '%s/connection/ftth/' % ENDPOINT

    if sConnectionMedia in ["ffth", "ftth"]:
        json_raw = get_request_api_url_result(api_url, sHeaders)
        if not json_raw:
            return

        my_measure = ""
        my_data = {}; my_tags = {}

        my_data['sfp_pwr_rx'] = json_raw['sfp_pwr_rx']  # scaled by 100 (in dBm)
        my_data['sfp_pwr_tx'] = json_raw['sfp_pwr_tx']
        my_data['sfp_alim_ok'] = 1 if json_raw['sfp_alim_ok'] else 0
        my_data['sfp_has_power_report'] = 1 if json_raw['sfp_has_power_report'] else 0
        my_data['sfp_has_signal'] = 1 if json_raw['sfp_has_signal'] else 0

        my_tags['conn_media'] = sConnectionMedia

        if 'sfp_model' in json_raw:
            my_tags['sfp_model'] = json_raw['sfp_model']
            my_tags['sfp_vendor'] = (replace_accents_string( json_raw['sfp_vendor'] ))[:12]  # limit to 12 chars
            my_tags['sfp_serial'] = json_raw['sfp_serial']

        OUTPUT_DATA_FINAL['conn_%s' % sConnectionMedia] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# xDSL specific -----------------------------------------------------------
def get_conn_xdsl_status(sHeaders, sConnectionMedia):
    api_url = '%s/connection/xdsl/' % ENDPOINT

    if sConnectionMedia == "xdsl":
        json_raw = get_request_api_url_result(api_url, sHeaders)
        if not json_raw:
            return

        my_measure = ""
        my_data = {}; my_tags = {}

        my_data['xdsl_modulation'] = json_raw['status']['modulation'] + " ("+json_raw['status']['protocol']+")"
        my_data['xdsl_uptime'] = json_raw['status']['uptime']  # in seconds

        CONVERT_XDSL_STATUS = { "down": 0,           # unsynchronized
                                "training": 1,       # synchronizing step 1/4
                                "started": 2,        # synchronizing step 2/4
                                "chan_analysis": 3,  # synchronizing step 3/4
                                "msg_exchange": 4,   # synchronizing step 4/4
                                "showtime": 5,       # ready
                                "disabled": -1       # disabled
                            }
        my_data['xdsl_status'] = CONVERT_XDSL_STATUS.get( json_raw['status']['status'], 999)    # set to 999 for unknown state

        for sDir in ['down', 'up']:
            my_data['xdsl_%s_es' % sDir] =   json_raw[sDir]['es']    # increment
            my_data['xdsl_%s_attn' % sDir] = json_raw[sDir]['attn']  # in dB
            my_data['xdsl_%s_snr' % sDir] =  json_raw[sDir]['snr']   # in dB
            my_data['xdsl_%s_rate' % sDir] = json_raw[sDir]['rate']  # ATM rate in kbit/s
            my_data['xdsl_%s_hec' % sDir] =  json_raw[sDir]['hec']   # increment
            my_data['xdsl_%s_crc' % sDir] =  json_raw[sDir]['crc']   # increment
            my_data['xdsl_%s_ses' % sDir] =  json_raw[sDir]['ses']   # increment
            my_data['xdsl_%s_fec' % sDir] =  json_raw[sDir]['fec']   # increment
            my_data['xdsl_%s_maxrate' % sDir] = json_raw[sDir]['maxrate']  # ATM max rate in kbit/s

            # older api compatibility
            if 'rtx_tx' in json_raw[sDir]:
                my_data['xdsl_%s_rtx_tx' % sDir] = json_raw[sDir]['rtx_tx']       # G.INP on/off
                my_data['xdsl_%s_rtx_c' % sDir] =  json_raw[sDir]['rtx_c']        # G.INP corrected
                my_data['xdsl_%s_rtx_uc' % sDir] = json_raw[sDir]['rtx_uc']       # G.INP uncorrected

            # new api v7+
            else:
                my_data['xdsl_%s_rtx_tx' % sDir] = json_raw[sDir]['rxmt']         # G.INP on/off
                my_data['xdsl_%s_rtx_c' % sDir] =  json_raw[sDir]['rxmt_corr']    # G.INP corrected
                my_data['xdsl_%s_rtx_uc' % sDir] = json_raw[sDir]['rxmt_uncorr']  # G.INP uncorrected

        my_tags['conn_media'] = sConnectionMedia
        my_tags['xdsl_status'] = json_raw['status']['status']   # also as a tag
        my_tags['xdsl_modulation'] = json_raw['status']['modulation']
        my_tags['xdsl_protocol'] = json_raw['status']['protocol']

        OUTPUT_DATA_FINAL['conn_%s' % sConnectionMedia] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# LTE specific ------------------------------------------------------------
def get_conn_lte_status(sHeaders):
    api_url = '%s/connection/lte/config/' % ENDPOINT
    json_raw = get_request_api_url_result(api_url, sHeaders)

    if not json_raw:
        return

    my_measure = ""
    my_data = {}; my_tags = {}

    my_data['lte_enabled'] = 1 if json_raw['enabled'] else 0
    my_data['lte_state'] = 1 if json_raw['state'] == 'connected' else 0
    # my_data['lte_fsm_state'] = json_raw['fsm_state']  # string with missing informations. values are : 'poll_network', and ?

    my_tags['conn_media'] = "lte"
    OUTPUT_DATA_FINAL['conn_lte_state'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


    if 'network' in json_raw:
        my_data = {}; my_tags = {}

        my_data['lte_net_pdn_up'] = 1 if json_raw['network']['pdn_up'] else 0

        my_tags['conn_media'] = "lte"
        my_tags['lte_net_ipv4'] = json_raw['network']['ipv4']
        my_tags['lte_net_ipv6'] = json_raw['network']['ipv6']
        OUTPUT_DATA_FINAL['conn_lte_pdn'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


    if 'radio' in json_raw:
        my_data = {}; my_tags = {}

        my_data['lte_radio_associated'] = 1 if json_raw['radio']['associated'] else 0
        my_data['lte_radio_plmn'] = json_raw['radio']['plmn']
        my_data['lte_radio_signal_level'] = json_raw['radio']['signal_level']
        my_data['lte_radio_ue_active'] = 1 if json_raw['radio']['ue_active'] else 0

        my_tags['conn_media'] = "lte"
        my_tags['lte_radio_gcid'] = json_raw['radio']['gcid']
        OUTPUT_DATA_FINAL['conn_lte_radio'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

        # add the band capabilities
        for sBand in json_raw['radio']['band']:
            my_band_data = {}; my_band_tags = {}

            my_band_data['lte_rband_enabled'] = 1 if sBand['enabled'] else 0
            my_band_data['lte_rband_bandwidth'] = sBand['bandwidth']  # ? no idea
            my_band_data['lte_rband_pci'] = sBand['pci']
            my_band_data['lte_rband_rsrp'] = sBand['rsrp']
            my_band_data['lte_rband_rsrq'] = sBand['rsrq']
            my_band_data['lte_rband_rssi'] = sBand['rssi']

            my_band_tags['band'] = sBand['band']  # should be a number
            OUTPUT_DATA_FINAL['conn_lte_band_%s' % str(sBand)] = {'measure': my_measure, 'tags': my_band_tags, 'data': my_band_data}


    if 'sim' in json_raw:
        my_sim_data = {}; my_sim_tags = {}

        my_sim_data['lte_sim'] = 1 if json_raw['sim']['present'] else 0
        my_sim_data['lte_sim_pin_locked'] = 1 if json_raw['sim']['pin_locked'] else 0
        my_sim_data['lte_sim_pin_remaining'] = json_raw['sim']['pin_remaining']
        my_sim_data['lte_sim_puk_locked'] = 1 if json_raw['sim']['puk_locked'] else 0
        my_sim_data['lte_sim_puk_remaining'] = json_raw['sim']['puk_remaining']

        my_sim_tags['conn_media'] = "lte"
        my_sim_tags['sim_iccid'] = json_raw['sim']['iccid']     # serial number / global uid for the sim card
        OUTPUT_DATA_FINAL['conn_lte_sim'] = {'measure': my_measure, 'tags': my_sim_tags, 'data': my_sim_data}


# DHCP status : configuration ---------------------------------------------
def get_dhcp_config(sHeaders):
    api_url = '%s/dhcp/config/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "dhcp"
    my_data = {}; my_tags = {}

    my_data['dhcp_enabled'] = 1 if json_raw['enabled'] else 0
    my_data['dhcp_sticky_assign'] = 1 if json_raw['sticky_assign'] else 0
    my_data['dhcp_always_broadcast'] = 1 if json_raw['always_broadcast'] else 0

    my_tags['dhcp_gateway'] = json_raw['gateway']
    my_tags['dhcp_ip_range_start'] = json_raw['ip_range_start']
    my_tags['dhcp_ip_range_end'] = json_raw['ip_range_end']
    my_tags['dhcp_netmask'] = json_raw['netmask']

    aDnsLst = []
    for d in json_raw['dns']:
        if len( d.strip() ) > 0:
            aDnsLst.append(d)
    my_tags['dhcp_dns'] = ",".join(aDnsLst)  # TODO: maybe not a good idea to do a join()

    OUTPUT_DATA_FINAL['dhcp_config'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# DHCP status : dynamic ---------------------------------------------------
def get_dhcp_dynamic(sHeaders):
    api_url = '%s/dhcp/dynamic_lease/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    nLeaseCount = 0
    my_measure = "dhcp"
    for i in json_raw:
        my_data = {}; my_tags = {}

        # my_data['dhcp_lease_ip'] = i['ip']  # should be set only as a tag
        my_data['dhcp_lease_static'] = 1 if i['is_static'] else 0    # no need for _dhcp_static with this metric
        my_data['dhcp_lease_refresh_time'] = i['refresh_time']       # in sec
        my_data['dhcp_lease_assign_time'] = i['assign_time']         # date
        my_data['dhcp_lease_remaining_time'] = i['lease_remaining']  # in sec

        my_data['dhcp_lease_active'] = 1 if i['host']['active'] else 0
        my_data['dhcp_lease_reachable'] = 1 if i['host']['reachable'] else 0
        my_data['dhcp_lease_last_time_reachable'] = i['host']['last_time_reachable']    # date

        my_tags['client_mac'] = i['mac']
        my_tags['client_hostname'] = i['hostname']
        my_tags['client_ip'] = i['ip']
        my_tags['client_hostname'] = i['hostname']
        my_tags['client_primary_name'] = i['host']['primary_name']

        OUTPUT_DATA_FINAL['dhcp_dynlease_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}
        nLeaseCount += 1

    # add the lease count
    my_data = {}; my_tags = {}
    my_data['dhcp_lease_count'] = nLeaseCount
    OUTPUT_DATA_FINAL['dhcp_config_lease_count'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# DHCP status : static ----------------------------------------------------
def get_dhcp_static(sHeaders):
    api_url = '%s/dhcp/static_lease/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "dhcp"    # pylint: disable=unused-variable # noqa F841
    # TODO: not implemented


# Internal disk stats -----------------------------------------------------
def get_disk_stats(sHeaders):
    api_url = '%s/storage/disk/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "storage"
    for d in json_raw:
        my_data = {}; my_tags = {}

        my_data['disk_temp'] = d['temp']
        my_data['disk_total_bytes'] = d['total_bytes']
        my_data['disk_idle'] = 1 if d['idle'] else 0

        CONVERT_DISK_STATE = { "error": 99,
                               "enabled": 1,
                               "disabled": 0
                            }
        my_data['disk_state'] = CONVERT_DISK_STATE.get( d['state'], 0)  # default to 0 for unknown state

        my_data['disk_write_error'] = d.get('write_error_requests', 0)  # can be missing

        my_tags['hdd'] = d['id']
        my_tags['hdd_type'] = d['type']
        my_tags['hdd_model'] = d['model']
        my_tags['hdd_serial'] = d['serial']
        my_tags['hdd_table_type'] = d['table_type']

        OUTPUT_DATA_FINAL['disk_%s' % str(d)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

        for p in d.get('partitions'):
            my_data = {}; my_tags = {}

            my_data['diskfs_total_bytes'] =  p['total_bytes']
            my_data['diskfs_used_bytes'] =  p['used_bytes']
            my_data['diskfs_free_bytes'] =  p['free_bytes']

            my_tags['hdd'] = json_raw[d]['id']          # reuse some of the hdd tags
            my_tags['hdd_type'] = json_raw[d]['type']   # reuse some of the hdd tags
            my_tags['partition'] = p['id']
            my_tags['partition_label'] = p['label']
            my_tags['partition_fstype'] = p['fstype']
            my_tags['partition_state'] = p['state']
            try:
                my_tags['partition_path'] = base64.b64decode( p['path'] )
            except:             # pylint: disable=bare-except  # noqa: E722
                my_tags['partition_path'] = 'unknown'

            OUTPUT_DATA_FINAL['disk_%s_part_%s' % (str(d), str(p)) ] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Lan Browser -------------------------------------------------------------
def get_lan_browser_interfaces(sHeaders):
    api_url = '%s/lan/browser/interfaces/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "lan"
    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['lanhost_count'] = i['host_count']
        my_tags['lan_iface'] = i["name"]
        OUTPUT_DATA_FINAL['lan_browser_iface_%s' % str(i) ] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

        if i['host_count'] > 0:
            json_raw_iface = get_lan_browser_iface_hosts(sHeaders, i["name"])
            if json_raw_iface:
                for c in json_raw_iface:
                    my_data = {}; my_tags = {}

                    my_data['lanhost_reachable'] = 1 if c['reachable'] else 0
                    my_data['lanhost_first_activity'] = c['first_activity']
                    my_data['lanhost_last_activity'] = c['last_activity']
                    my_data['lanhost_last_time_reachable'] = c['last_time_reachable']
                    my_data['lanhost_persistent'] = 1 if c['persistent'] else 0

                    for lconn in c['l3connectivities']:
                        # "af" should have unique values
                        my_data['lanhost_%s_active' % lconn['af']] = 1 if lconn['active'] else 0
                        # already available in the iface data
                        # my_data['lanhost_%s_reachable' % lconn['af']] = 1 if lconn['reachable'] else 0
                        # my_data['lanhost_%s_last_activity' % lconn['af']] = lconn['last_activity']
                        # my_data['lanhost_%s_last_time_reachable' % lconn['af']] = lconn['last_time_reachable']
                        my_tags['lan_%s' % lconn['af']] = lconn['addr']

                    my_tags['lan_type'] = c['host_type'].lower()
                    my_tags['lan_primary_name'] = c['primary_name']
                    my_tags['lan_vendor'] = (replace_accents_string( c['vendor_name'] ))[:12]  # limit to 12 chars
                    my_tags['lan_%s' % c['l2ident']['type']] = c['l2ident']['id']  # should be something like: mac_address = ":m:a:c:"
                    my_tags['lan_iface'] = i["name"]

                    OUTPUT_DATA_FINAL['lan_browser_client_%s' % str(i) ] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# used by get_lan_browser_interfaces()
def get_lan_browser_iface_hosts(sHeaders, iface):
    api_url = '%s/lan/browser/%s/' % (ENDPOINT, iface)
    return get_request_api_url_result(api_url, sHeaders)


# General infos -----------------------------------------------------------
def get_system_config(sHeaders):    # pylint: disable=too-many-statements
    api_url = '%s/system/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = ""
    my_data = {}; my_tags = {}

    my_data['sys_uptime'] = json_raw.get('uptime_val', 0)  # Uptime, in seconds
    my_data['sys_authenticated'] = 1 if json_raw['box_authenticated'] else 0  # box at step 6
    my_data['firmware_version'] = json_raw['firmware_version']
    my_data['sys_disk_status'] = 1 if json_raw['disk_status'] == 'active' else 0

    my_tags['hw_firmware'] = json_raw['firmware_version']
    my_tags["hw_serial"] = json_raw['serial']

    OUTPUT_TAGS_GLOBAL["hw_board"] = json_raw['board_name']

    # v8+ API
    if 'model_info' in json_raw:
        # disabled for now : too much metric and not really usefull
        # for sCapability in ['has_dsl',
        #           'has_dect',
        #           'has_eco_wifi',
        #           'has_ext_telephony',
        #           'has_femtocell_exp',
        #           'has_fixed_femtocell',
        #           'has_lcd_orientation',
        #           'has_home_automation',
        #           'has_lan_sfp',
        #           'has_led_strip',
        #           'has_separate_internal_storage',
        #           'has_speakers_jack',
        #           'has_standby',
        #           'has_vm',
        #           'has_wop'
        #         ]:
        #     my_data['minfo_%s' % sCapability] = 1 if json_raw.get(sCapability) else 0

        my_data['minfo_customer_hdd_slots'] = json_raw.get('customer_hdd_slots', -1)
        my_data['minfo_internal_hdd_size'] = json_raw.get('internal_hdd_size', -1)

        my_tags["hw_mac"] = json_raw['mac']
        my_tags['hw_model_pretty'] = json_raw['model_info']['pretty_name']
        my_tags["hw_model"] =  json_raw['model_info']['name']
        my_tags["net_operator"] =  json_raw['model_info']['net_operator']

    # old API v5- compatibility
    else:
        my_tags["hw_mac"] = "n/a"
        sysmodel_json_raw = get_system_model_api5()
        # no sublevel for _system_model in the results
        my_tags["hw_model"] = sysmodel_json_raw['box_model']

    OUTPUT_DATA_FINAL['system'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

    # fan & temperature sensors
    # old API v5- compatibility
    if "fan_rpm" in json_raw:
        my_data = {}; my_tags = {}

        my_data['sys_fan_rpm'] = json_raw['fan_rpm']  # rpm
        my_data['sys_temp_sw'] = json_raw['temp_sw']  # Temp Switch, degree Celcius

        my_data['sys_temp_cpub'] = json_raw['temp_cpub']  # Temp CPU Broadcom, degree Celcius
        my_data['sys_temp_cpum'] = json_raw['temp_cpum']  # Temp CPU Marvell, degree Celcius

        my_tags['sensor'] = "main"
        my_tags['sensor_name'] = "main"

        OUTPUT_DATA_FINAL['system_sensors'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

    # v8+ API
    else:
        # fan sensors
        nCount = 0
        for i in json_raw['fans']:
            my_data = {}; my_tags = {}

            my_data['sys_fan_rpm'] = i['value']  # rpm

            my_tags['fan'] = i['id']
            my_tags['fan_name'] = replace_accents_string( i['name'] )

            OUTPUT_DATA_FINAL['system_sensors_fan_%s' % i] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}
            nCount += 1

        # add the fan count
        my_data = {}; my_tags = {}
        my_data['sys_fan_count'] = nCount
        OUTPUT_DATA_FINAL['system_sensors_fan_count'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


        # temperature sensors
        nCount = 0
        for i in json_raw['sensors']:
            my_data = {}; my_tags = {}

            my_data['sys_temp'] = i['value']  # Temp degree Celcius

            my_tags['sensor'] = i['id']
            my_tags['sensor_name'] = replace_accents_string( i['name'] )

            OUTPUT_DATA_FINAL['system_sensors_temp_%s' % i] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}
            nCount += 1

        # add the sensor count
        my_data = {}; my_tags = {}
        my_data['sys_temp_count'] = nCount
        OUTPUT_DATA_FINAL['system_sensors_temp_count'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# used by get_system_config()
def get_system_model_api5():
    # the model is on the "/api_version" path which is public
    api_url = 'http://%s/api_version' % (ENDPOINT_HOST)
    r = requests.get(api_url, timeout=ENDPOINT_REQUEST_TIMEOUT)
    debug_output( json.dumps(r.json(), indent=4, sort_keys=True) )
    return r.json()


# Switch status -----------------------------------------------------------
def get_switch_status(sHeaders, bSwitchPortsGetStats = 0):      # pylint: disable=too-many-statements,too-many-locals # noqa C901,R0914,R0915
    api_url = '%s/switch/status/' % ENDPOINT

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "switch"
    nSwitchPortCount = 0
    nTimeNowUnix = int(time.time())
    PATCH_FIX_RATE_UP_BYTES_UP_rateup = 0
    PATCH_FIX_RATE_UP_BYTES_UP_bytesup = 0

    for i in json_raw:
        my_data = {}; my_tags = {}
        nSwitchPortCount += 1

        # 0 down, 1 up
        my_data['switch_link'] = 1 if i['link'].lower() == "up" else 0
        # 0 half, 1 full
        my_data['switch_duplex'] = 1 if i['duplex'].lower() == "full" else 0
        my_data['switch_speed'] = int( i['speed'] )

        my_tags['switch_port'] = int(i['id'])
        my_tags['switch_mode'] = i['mode']
        if 'name' in i:
            my_tags['switch_name'] = i['name']

        # clients connected to the port
        nMacCount = 0
        if 'mac_list' in i:
            for m in i['mac_list']:
                my_data_client = {}; my_tags_client = {}
                nMacCount += 1

                my_data_client['client_last_seen'] = nTimeNowUnix

                my_tags_client['switch_port'] = int(i['id'])        # reuse the port id
                my_tags_client['mac'] = m['mac']
                my_tags_client['hostname'] = m.get('hostname', "unknown")
                if len( my_tags_client['hostname'] ) == 0:
                    my_tags_client['hostname'] = "unknown"

                OUTPUT_DATA_FINAL['switch_port_mac_client_%s' % m] = {'measure': my_measure, 'tags': my_tags_client, 'data': my_data_client}

        # add the client count to the main data
        my_data['switch_client_count'] = nMacCount
        OUTPUT_DATA_FINAL['switch_%s' % i['id'] ] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


        # current port status
        if bSwitchPortsGetStats:
            json_raw_port = get_switch_port_stats(sHeaders, str(i['id']))
            if json_raw_port:
                my_data_port = {}; my_tags_port = my_tags     # reuse the same tags as the port

                # these metrics exist for both "rx_*" and "tx_*"
                my_data_port['switch_rx_bytes_rate'] = json_raw_port['rx_bytes_rate']  # bytes/s
                my_data_port['switch_tx_bytes_rate'] = json_raw_port['tx_bytes_rate']  # bytes/s

                # these metrics only exist on one mode
                my_data_port['switch_err_packets'] = json_raw_port['rx_err_packets']
                my_data_port['switch_discard_packets'] = json_raw_port['rx_discard_packets']
                my_data_port['switch_collisions'] = json_raw_port['tx_collisions']

                OUTPUT_DATA_FINAL['switch_port_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags_port, 'data': my_data_port}

                # fix for connection stats - part 1 : WAN rate_up & bytes_up are cumulated with their *_down counterpart - reuse the switch data
                if PATCH_FIX_RATE_UP_BYTES_UP:
                    PATCH_FIX_RATE_UP_BYTES_UP_rateup = PATCH_FIX_RATE_UP_BYTES_UP_rateup + int( json_raw_port['rx_bytes_rate'] )
                    PATCH_FIX_RATE_UP_BYTES_UP_bytesup = PATCH_FIX_RATE_UP_BYTES_UP_bytesup + int( json_raw_port['rx_good_bytes'] )

    # add the port count
    my_data = {}; my_tags = {}
    my_data['switch_port_count'] = nSwitchPortCount
    OUTPUT_DATA_FINAL['switch_port_count'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

    # fix for connection stats - part 2 : WAN rate_up & bytes_up are cumulated with their *_down counterpart - reuse the switch data
    if PATCH_FIX_RATE_UP_BYTES_UP:
        OUTPUT_DATA_FINAL['connection']['data']['rate_up'] = PATCH_FIX_RATE_UP_BYTES_UP_rateup
        OUTPUT_DATA_FINAL['connection']['data']['bytes_up'] = PATCH_FIX_RATE_UP_BYTES_UP_bytesup


# used by get_switch_status() for each network port
def get_switch_port_stats(sHeaders, port):
    api_url = '%s/switch/port/%s/stats' % (ENDPOINT, port)
    return get_request_api_url_result(api_url, sHeaders)


# Virtual machines : system info ------------------------------------------
def get_virtualmachine_sysinfo(sHeaders):
    api_url = '%s/vm/info/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "virtualmachine"
    my_data = {}; my_tags = {}

    my_data['total_memory'] = json_raw['total_memory']
    my_data['used_memory'] = json_raw['used_memory']
    my_data['total_cpus'] = json_raw['total_cpus']
    my_data['usb_ports_count'] = len( json_raw['usb_ports'] )
    my_data['usb_used'] = 1 if json_raw['usb_used'] else 0

    # no tags here
    OUTPUT_DATA_FINAL['vm_host_sysinfo'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Virtual machines --------------------------------------------------------
def get_virtualmachines(sHeaders):
    api_url = '%s/vm/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "virtualmachine"
    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['vm_status'] = 1 if i['status'] == "running" else 0
        my_data['vm_memory'] = i['memory']
        my_data['vm_vcpus'] = i['vcpus']
        my_data['vm_enable_screen'] = 1 if i['enable_screen'] else 0
        my_data['vm_bind_usb_ports_count'] = len(i['bind_usb_ports'])
        my_data['vm_enable_cloudinit'] = 1 if i['enable_cloudinit'] else 0

        my_tags['vm'] = i['id']
        my_tags['vm_name'] = i['name']
        my_tags['vm_disk_path'] = base64.b64decode( i['disk_path'] )
        my_tags['vm_disk_type'] = i['disk_type']
        my_tags['vm_cd_path'] = base64.b64decode( i.get("cd_path", "bm9uZQo=") )     # "none" => "bm9uZQo="
        my_tags['vm_cloudinit_hostname'] = i.get("cloudinit_hostname", "")
        my_tags['vm_mac'] = i['mac']
        my_tags['vm_os'] = i['os']

        OUTPUT_DATA_FINAL['vm_info_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# VPN servers -------------------------------------------------------------
def get_vpn_servers(sHeaders):
    api_url = '%s/vpn/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "vpn_server"
    for i in json_raw:
        my_data = {}; my_tags = {}

        CONVERT_VPNSRV_STATE = { "error": 99,
                                 "started": 1
                               }
        my_data['vpnsrv_state'] = CONVERT_VPNSRV_STATE.get( i['state'], 0)  # default to 0 for unknown state
        my_data['vpnsrv_connection_count'] = i['connection_count']
        my_data['vpnsrv_auth_connection_count'] = i['auth_connection_count']

        my_tags['vpn_type'] = i['type']
        my_tags['vpn_name'] = i['name']

        json_raw_conf = get_vpn_server_config(sHeaders, i['name'])
        if json_raw_conf:
            my_data['vpnsrv_enabled'] = 1 if json_raw_conf['enabled'] else 0

            if 'port' in json_raw_conf:
                my_tags['vpn_port'] = json_raw_conf['port']
            elif 'port_nat' in json_raw_conf:
                my_tags['vpn_port'] = json_raw_conf['port_nat']
            my_tags['vpn_ip_start'] = json_raw_conf.get('ip_start', '')
            my_tags['vpn_ip_end'] = json_raw_conf.get('ip_end', '')
            my_tags['vpn_ip6_start'] = json_raw_conf.get('ip6_start', '')
            my_tags['vpn_ip6_end'] = json_raw_conf.get('ip6_end', '')

        OUTPUT_DATA_FINAL['vpn_srv_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# used by get_vpn_servers()
def get_vpn_server_config(sHeaders, sVpnSrvName):
    api_url = '%s/vpn/%s/config/' % (ENDPOINT, sVpnSrvName)
    return get_request_api_url_result(api_url, sHeaders)


# VPN servers -------------------------------------------------------------
def get_vpn_server_connection(sHeaders):
    # the server name does not seems to be required
    api_url = '%s/vpn/connection/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "vpn_server"
    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['vpnsrv_conn_authenticated'] = 1 if i['authenticated'] else 0
        my_data['vpnsrv_conn_auth_time'] = i['auth_time']
        my_data['vpnsrv_conn_rx_bytes'] = i['rx_bytes']
        my_data['vpnsrv_conn_tx_bytes'] = i['tx_bytes']

        my_tags['conn_id'] = i['id']
        my_tags['conn_user'] = i['user']
        my_tags['vpn_name'] = i['vpn']      # use the same tag as for the server's name
        my_tags['conn_src_ip'] = i['src_ip']
        my_tags['conn_local_ip'] = i['local_ip']

        OUTPUT_DATA_FINAL['vpn_srv_conn_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# VPN integrated client : config ------------------------------------------
def get_vpn_integrated_client_config(sHeaders):
    api_url = '%s/vpn_client/config/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "vpn_client"

    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['vpnclient_state'] = 1 if i['active'] else 0

        my_tags['ivc'] = i['id']
        my_tags['ivc_type'] = i['type']
        my_tags['ivc_description'] = i['description']
        if 'conf_pptp' in i:
            my_tags['ivc_username'] = i['username']
            my_tags['ivc_remote_host'] = i['remote_host']
        elif 'conf_wireguard' in i:
            my_tags['ivc_mtu'] = i['mtu']
            my_tags['ivc_remote_host'] = i['remote_addr']
            my_tags['ivc_remote_port'] = i['remote_port']

        OUTPUT_DATA_FINAL['vpn_client_config_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# VPN integrated client : status ------------------------------------------
def get_vpn_integrated_client_status(sHeaders):
    api_url = '%s/vpn_client/status' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "vpn_client"
    my_data = {}; my_tags = {}

    if not json_raw['enabled']:     # the data will be absent
        my_data['vpnconn_enabled'] = 0
        my_data['vpnconn_state'] = 0

        OUTPUT_DATA_FINAL['vpn_client_status'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}
        return

    my_data['vpnconn_enabled'] = 1
    my_data['vpnconn_state'] = 1 if json_raw['state'] == "up" else 0
    my_data['vpnconn_last_try'] = json_raw['last_try']                # unix time or 0
    my_data['vpnconn_last_up'] = json_raw['last_up']                  # unix time or 0
    my_data['vpnconn_next_try'] = json_raw['next_try']                # secs remaining
    my_data['vpnconn_rate_up'] = json_raw['stats']['rate_up']         # bytes/s
    my_data['vpnconn_rate_down'] = json_raw['stats']['rate_down']     # bytes/s
    my_data['vpnconn_bytes_up'] = json_raw['stats']['bytes_up']       # total bytes
    my_data['vpnconn_bytes_down'] = json_raw['stats']['bytes_down']   # total bytes

    my_tags['type'] = json_raw['type']
    my_tags['active_vpn_description'] = json_raw['active_vpn_description']
    my_tags['active_vpn'] = json_raw['active_vpn']
    if 'ipv4' in json_raw:
        my_tags['ipv4'] = json_raw['ipv4']['ip_mask']['ip']
        my_tags['ipv4_mask'] = json_raw['ipv4']['ip_mask']['mask']
        my_tags['ipv4_gateway'] = json_raw['ip_v4']['gateway']
        my_tags['ipv4_domain'] = json_raw['ip_v4']['domain']
        my_tags['ipv4_provider'] = json_raw['ip_v4']['provider']

    OUTPUT_DATA_FINAL['vpn_client_status'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

    # specific for the last error, having both the number as a metric and an extra tag with the description
    my_data = {}    # keep the tags from vpnconn client
    CONVERT_VPNCONN_ERROR = { "none": 0,
                              "internal": 1,
                              "authentication_failed": 2,
                              "auth_failed": 3,
                              "resolv_failed": 4,
                              "connect_timeout": 5,
                              "connect_failed": 6,
                              "setup_control_failed": 7,
                              "setup_call_failed": 8,
                              "protocol": 9,
                              "remote_terminated": 10,
                              "remote_disconnect": 11
                            }
    my_data['vpnconn_last_error'] = CONVERT_VPNCONN_ERROR.get( json_raw['last_error'], 999)

    my_tags['last_error_desc'] = json_raw['last_error']
    OUTPUT_DATA_FINAL['vpn_client_status_error'] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# Wifi stats --------------------------------------------------------------
def get_wifi_ap_stats(sHeaders):
    api_url = '%s/wifi/ap/' % (ENDPOINT)

    json_raw = get_request_api_url_result(api_url, sHeaders)
    if not json_raw:
        return

    my_measure = "wifi"
    for i in json_raw:
        my_data = {}; my_tags = {}

        my_data['wifi_state'] = 1 if i['status']['state'] == "active" else 0

        my_tags['wifi_ap'] = i['id']
        my_tags['wifi_ap_name'] = i['name']
        my_tags['wifi_ap_band'] = i['config']['band']

        if my_data['wifi_state'] == 1:
            # also available under 'config' but 'status' gives the final values
            my_data['wifi_channel_width'] = i['status']['channel_width']
            my_data['wifi_primary_channel'] = i['status']['primary_channel']
            my_data['wifi_secondary_channel'] = i['status']['secondary_channel']

        OUTPUT_DATA_FINAL['wifi_ap_%s' % str(i)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}

        if i['status']['state'] == "active":
            json_raw_ap = get_wifi_ap_stations(sHeaders, i['id'])
            if json_raw_ap:
                for s in json_raw_ap:
                    my_data = {}; my_tags = {}

                    my_data['wifi_station_tx_bytes'] = s['tx_bytes']
                    my_data['wifi_station_rx_bytes'] = s['rx_bytes']
                    my_data['wifi_station_signal'] = s['signal']                # in db, negative value
                    my_data['wifi_station_conn_duration'] = s['conn_duration']  # in secs
                    my_data['wifi_station_inactive'] = s['inactive']            # in secs

                    my_tags['wifi_ap'] = i['id']            # reuse some of the ap tags
                    my_tags['wifi_ap_name'] = i['name']     # reuse some of the ap tags
                    my_tags['wifi_station_hostname'] = s['hostname']
                    my_tags['wifi_station_mac'] = s['mac']
                    my_tags['wifi_station'] = s['id']
                    my_tags['wifi_station_bssid'] = s['bssid']

                    OUTPUT_DATA_FINAL['wifi_station_%s' % str(s)] = {'measure': my_measure, 'tags': my_tags, 'data': my_data}


# used by get_wifi_ap_stats()
def get_wifi_ap_stations(sHeaders, nWifiApStation):
    api_url = '%s/wifi/ap/%s/stations' % (ENDPOINT, nWifiApStation)
    return get_request_api_url_result(api_url, sHeaders)


# Format the measurement name -------------------------------------------------
def do_format_for_output_measurement(sOutputType, sMeasureSuffix):
    if len(sMeasureSuffix) == 0:
        return OUTPUT_MEASUREMENT["name"]

    return OUTPUT_MEASUREMENT["name"] + OUTPUT_MEASUREMENT[sOutputType.lower()]["measure_separator"] + sMeasureSuffix


# Format the tags{"name": value, "name2": ...} in a single string -------------
def do_format_for_output_tags(sOutputType, aTagList):
    sRet = ""
    sSeparator = OUTPUT_MEASUREMENT[sOutputType.lower()]["tag_separator"]

    for sTagName, sTagValue in aTagList.items():
        if sOutputType == "influxdb" and isinstance(sTagValue, str):
            # spaces must be escaped for influx v1 as " in a tag name or value are read as a litteral
            sTagValue = sTagValue.replace(' ', '\ ')        # pylint: disable=anomalous-backslash-in-string  # noqa: W605
        # Graphite has no requirement

        # as the tags are following the measurement, the result must start with the usual separator (, or ;)
        sRet = sRet + sSeparator + sTagName + "=" + str(sTagValue)
    return sRet


# Output ----------------------------------------------------------------------
# Either influxdb or graphite
def do_output_metrics(sOutputFormat = "influxdb"):

    # generate the global tag list for the output
    sOutputTagsGlobal = do_format_for_output_tags(sOutputFormat, OUTPUT_TAGS_GLOBAL)

    # Switching between outputs formats
    if sOutputFormat == 'influxdb':
        # Prepping Influxdb Data format
        # timestamp is not required for influxdb

        # Output the information - format is : measurement_measure,tag=name,tag=name metric=value,metric=value time
        # each entry is in the form : {'tags': my_tags{}, 'data': my_data{}}
        for x in OUTPUT_DATA_FINAL:        # pylint: disable=consider-using-dict-items
            my_measure = OUTPUT_DATA_FINAL[x].get('measure', "")
            my_tags = OUTPUT_DATA_FINAL[x].get('tags', {})
            my_data = OUTPUT_DATA_FINAL[x]['data']

            sOutputMeasurement = do_format_for_output_measurement(sOutputFormat, my_measure)
            sOutputTagsMetric =  do_format_for_output_tags(sOutputFormat, my_tags)

            for m in my_data:
                if isinstance(my_data[m], str):
                    my_data[m] = "\"" + my_data[m] + "\""
                # TODO: switch to a single print() for the full "my_data[]" as influxdb accepts multiple metrics for the same tags on the same line
                print(sOutputMeasurement + sOutputTagsGlobal + sOutputTagsMetric + " " + m + "=" + str(my_data[m]))

    else:
        # Prepping Graphite Data format
        nTimestamp = int(time.time())

        # Output the information - format is : measurement.measure.metric;tag=name;tag=name value time
        # each entry is in the form : {'tags': my_tags{}, 'data': my_data{}}
        for x in OUTPUT_DATA_FINAL:        # pylint: disable=consider-using-dict-items
            my_measure = OUTPUT_DATA_FINAL[x].get('measure', "")
            my_tags = OUTPUT_DATA_FINAL[x].get('tags', {})
            my_data = OUTPUT_DATA_FINAL[x]['data']

            sOutputMeasurement = do_format_for_output_measurement(sOutputFormat, my_measure)
            sOutputTagsMetric = do_format_for_output_tags(sOutputFormat, my_tags)

            for m in my_data:
                print(sOutputMeasurement + "." + m + sOutputTagsGlobal + sOutputTagsMetric + " " + str(my_data[m]) + " " + str(nTimestamp))


# retrieve the auth data from the config file ---------------------------------
def get_auth(cfg_file):
    global ENDPOINT
    global ENDPOINT_SSL

    debug_output('get_auth() => cred file: ' + cfg_file)

    f = configp.RawConfigParser()
    f.read(cfg_file, encoding='latin-1')

    try:
        _ = f.get("general", "track_id")
        _ = f.get("general", "app_token")
    except configp.NoSectionError:
        print("Config is invalid, the auth token is missing.")
        return None

    # set the global variables
    ENDPOINT = f.get('api', 'api_endpoint', fallback=ENDPOINT_FAILSAFE)
    ENDPOINT_SSL = int( f.get('api', 'api_ssl', fallback=ENDPOINT_SSL) )

    return {'track_id': f.get('general', 'track_id'),
            'app_token': f.get('general', 'app_token'),
            'api_endpoint': ENDPOINT,
            'api_ssl': ENDPOINT_SSL,
            }


# write the auth config file --------------------------------------------------
def write_auth(sConfigFile, auth_infos):
    f = configp.RawConfigParser()

    f.add_section("general")
    f.set("general", "track_id", auth_infos['track_id'])
    f.set("general", "app_token", auth_infos["app_token"])

    f.add_section("api")
    f.set("api", "api_endpoint", ENDPOINT)
    f.set("api", "api_ssl", str(ENDPOINT_SSL) )

    with open(sConfigFile, "tw", encoding='latin-1') as authFile:
        f.write(authFile)

    # owner=rw, group=r
    os.chmod(sConfigFile, 0o640 )


# register the client to the box ----------------------------------------------
def do_register(sConfigFile, creds):
    if creds is not None:
        if 'track_id' in creds and 'app_token' in creds:
            print("Already registered, exiting")
            return

    register_infos = None

    print("Registering on %s ..." % ENDPOINT)

    headers = {'Content-type': 'application/json'}
    app_info = {
        'app_id': APP_ID,
        'app_name': APP_NAME,
        'app_version': APP_VERSION,
        'device_name': socket.gethostname()
    }
    json_payload = json.dumps(app_info)

    r = requests.post('%s/login/authorize/' % ENDPOINT, headers=headers, data=json_payload, verify=SSL_VERIFY, timeout=ENDPOINT_REQUEST_TIMEOUT)

    if r.status_code != 200:
        print('Failed registration: %s\n' % r.text)
        sys.exit(1)

    register_infos = r.json()

    write_auth(sConfigFile, register_infos['result'])
    print("Don't forget to accept the authentication on the Freebox panel !")


# show the current registration status ----------------------------------------
def register_status(sConfigFile, creds):
    if not creds:
        print("Registration status: invalid config, the auth token is missing.")
        print("Please run `%s --register` to register app." % sys.argv[0])
        print("Use `%s --help` for more information." % sys.argv[0])
        sys.exit(1)

    print("Registration status:")
    print("Credential file: %s" % sConfigFile)
    print("  track_id: %s" % creds["track_id"])
    print("  app_token: %s***HIDDEN***" % creds["app_token"][:4] )
    print("  api_endpoint: %s" % creds["api_endpoint"])
    print("  api_ssl: %s" % creds["api_ssl"])


# Add command line arguments --------------------------------------------------
def parserInitWithArguments():
    oParser = argparse.ArgumentParser(description = "%s (%s)" % (APP_NAME, APP_VERSION))

    oParser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Activate the debug mode and print the retrieved data")
    oParser.add_argument('-c', '--config', dest='config_file', metavar='/path/to/file', default=CONFIG_FILE, help="Full path to the credential file. Default is: " + CONFIG_FILE)
    oParser.add_argument('-r', '--register', action='store_true', help="Register the app with the Freebox API and cache the API url and version")
    oParser.add_argument('-s', '--register-status', dest='status', action='store_true', help="Get the registration status")
    oParser.add_argument('-f', '--format', dest='format', choices=['graphite', 'influxdb'], default='graphite', help="Specify output format between 'graphite' and 'influxdb'. Default is: graphite")
    oParser.add_argument('-e', '--endpoint', dest='endpoint', metavar='target-box', default=ENDPOINT_HOST, help="Specify the dns or ip of the box API endpoint. Default is: " + ENDPOINT_HOST)    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('--auth-hash-type', dest='endpoint_auth_hash_type', metavar='sha1|sha256|sha3_256|...', default=ENDPOINT_AUTH_HASH, help="Select the hash algorithm used when opening a session at the challenge step. Refer to hashlib documentation and the freebox API object SessionStart from /login/authorize for the supported types. Default is: " + ENDPOINT_AUTH_HASH)    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('--api-endpoint-detect-force', dest='endpoint_detect_force', action='store_true', help="Ignore the cache and force the detection of the api capabilities and version from the endpoint target. Allow some overrides.")    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('--api-endpoint-detect-ssl-domain', dest='endpoint_detect_domain_ssl', action='store_true', help="Use 'api_domain' and 'https_port' from the API response to detect the https URL. Not using this parameter will keep for SSL the url : https://" + ENDPOINT_HOST)    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('--api-version-force', dest='endpoint_api_force_major', metavar='version_major', default='', help="Override the API major version. Must be used with either '--register' or '--api-endpoint-detect-force'")    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('--ssl-no-verify', dest='ssl_verify', action='store_false', help="Disable the certificate validity test on ssl connections")
    oParser.add_argument('--ssl-ca-bundle-file', dest='ssl_ca_bundle_file', metavar='/path/to/file.pem', default=SSL_CUSTOM_CA_BUNDLE_FILE, help="Full path to the custom ssl CA bundle file in PEM format. Both the root and intermediate certs must be in the bundle. Default is: " + SSL_CUSTOM_CA_BUNDLE_FILE)    # pylint: disable=line-too-long # noqa C0301
    oParser.add_argument('-v', '--version', dest='version', action='store_true', help="Show the version and exit")

    oParser.add_argument('-C', '--status-call', dest='status_call', action='store_true', help="Get the phone call logs and history")
    oParser.add_argument('-X', '--status-dhcp', dest='status_dhcp', action='store_true', help="Get and show the dhcp status")
    oParser.add_argument('-D', '--status-disk', '--internal-disk-usage', dest='status_disk', action='store_true', help="Get and show the disks status")
    oParser.add_argument('-B', '--status-lan-browser', dest='status_lanbrowser', action='store_true', help="Get and show the hosts on the local network with the lan browser")
    oParser.add_argument('-L', '--status-lte', dest='status_lte', action='store_true', help="Get and show 4G/LTE aggregation status")
    oParser.add_argument('-H', '--status-sys', dest='status_sys', action='store_true', help="Get and show system status")
    oParser.add_argument('-P', '--status-ports', dest='status_ports', action='store_true', help="DEPRECATED: has no effect, integrated into --status-switch and kept for compatibility")
    oParser.add_argument('-S', '--status-switch', dest='status_switch', action='store_true', help="Get and show the switch and ports status")
    oParser.add_argument('-M', '--status-virtualmachines', dest='status_virtualmachine', action='store_true', help="Get and show the virtual machines status")
    oParser.add_argument('-V', '--status-vpnsrv', dest='status_vpnsrv', action='store_true', help="Get and show the VPN Servers status")
    oParser.add_argument('-Z', '--status-vpnclient', dest='status_vpnclient', action='store_true', help="Get and show the integrated VPN client status")
    oParser.add_argument('-W', '--status-wifi', dest='status_wifi', action='store_true', help="Get and show the Wifi status")

    # PATCH_FIX_RATE_UP_BYTES_UP
    oParser.add_argument('--patch-rate-up-bytes-up', dest='patch_rate_up_bytes_up', action='store_true', help="Fix the rate_up & bytes_up metrics which are cumulated with their *_down counterpart since 10/2024. See task 40445 for more information.\nThis requires the '--status-switch' parameter to be activated, and the freebox switch not used for LAN traffic aside for internet access")    # pylint: disable=line-too-long # noqa C0301

    return oParser


###############################################################################
# Main
if __name__ == '__main__':          # noqa C901

    parser = parserInitWithArguments()
    args = parser.parse_args()

    if args.version:
        print("Version: %s" % APP_VERSION)
        sys.exit(0)

    # applying the parameter values
    DEBUG = args.debug
    ENDPOINT_HOST = args.endpoint
    ENDPOINT_AUTH_HASH =  sanitize_string(args.endpoint_auth_hash_type)
    SSL_VERIFY = args.ssl_verify
    SSL_CUSTOM_CA_BUNDLE_FILE = args.ssl_ca_bundle_file
    CONFIG_FILE = args.config_file
    PATCH_FIX_RATE_UP_BYTES_UP = args.patch_rate_up_bytes_up

    if len(args.endpoint_api_force_major.strip()) > 0:
        ENDPOINT_API_MAJOR_FORCE = int(args.endpoint_api_force_major)
        if not args.endpoint_detect_force:
            print("Error: forcing the api major version cannot work without forcing the endpoint autodetection with '--api-endpoint-detect-force'")
            sys.exit(1)

    if DEBUG:
        print("%s version: %s" % (APP_NAME, APP_VERSION) )
        print("Python version: %s" % sys.version)

    # retrieve the authentication state
    auth = get_auth(CONFIG_FILE)
    set_api_ssl_verification()

    if args.register:
        get_api_endpoint_detect(args.endpoint_detect_domain_ssl)
        do_register(CONFIG_FILE, auth)
        sys.exit(0)

    elif args.status or not auth:
        register_status(CONFIG_FILE, auth)
        sys.exit(0)

    # Collecting the API data -------------------------------------------------
    if args.endpoint_detect_force:
        get_api_endpoint_detect(args.endpoint_detect_domain_ssl)

    headers = get_auth_header_for_session(auth, APP_ID)

    # Generic data - Fetch connection config & stats
    get_connection_config(headers)

    get_connection_stats(headers)   # will also update "DATA_CONNECTION_STATS_MEDIA"

    # FTTH & xDSL specifics
    if DATA_CONNECTION_STATS_MEDIA in ["ffth", "ftth"]:
        get_conn_ftth_status(headers, DATA_CONNECTION_STATS_MEDIA)

    elif DATA_CONNECTION_STATS_MEDIA == "xdsl":
        get_conn_xdsl_status(headers, DATA_CONNECTION_STATS_MEDIA)

    if args.status_lte:             # LTE can be present with xDSL or FTTH
        get_conn_lte_status(headers)

    if args.status_sys:
        get_system_config(headers)

    if args.status_switch:
        get_switch_status(headers, 1)

    if args.status_disk:            # internal disks
        get_disk_stats(headers)

    if args.status_wifi:
        get_wifi_ap_stats(headers)

    if args.status_dhcp:
        get_dhcp_config(headers)
        get_dhcp_dynamic(headers)
        get_dhcp_static(headers)    # TODO: not implemented

    if args.status_lanbrowser:
        get_lan_browser_interfaces(headers)

    if args.status_call:            # can be empty if the box has no WAN connection active
        get_call_account(headers)
        get_call_stats(headers)

    if args.status_virtualmachine:
        get_virtualmachine_sysinfo(headers)
        get_virtualmachines(headers)

    if args.status_vpnsrv:          # VPN servers
        get_vpn_servers(headers)
        get_vpn_server_connection(headers)

    if args.status_vpnclient:       # VPN integrated client
        get_vpn_integrated_client_config(headers)
        get_vpn_integrated_client_status(headers)

    # Add some data as global tags
    OUTPUT_TAGS_GLOBAL["api_endpoint"] = ENDPOINT
    OUTPUT_TAGS_GLOBAL["api_version"] = re.sub(r'.*://.*/v?[^0-9\.]+', '', ENDPOINT, flags=re.IGNORECASE)   # extract the api version used from the URL

    # pretty print the metrics to stdout
    do_output_metrics(args.format.lower())
