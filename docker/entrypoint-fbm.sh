#!/bin/bash
set -e

FB_MONITOR_BIN=/usr/local/py/freebox_monitor.py

export FB_MONITOR_CRED_FILE=${FB_MONITOR_CRED_FILE:-/data/.credentials}
export FB_TELEGRAF_OUTPUT=${FB_TELEGRAF_OUTPUT:-influx}
export FB_MONITOR_ARGS=${FB_MONITOR_ARGS:---status-sys}


if [ "${1:0:1}" = '-' ]; then
    "${FB_MONITOR_BIN}" "$@"
else 
    set -- telegraf -config /etc/telegraf/telegraf.conf -config-directory /etc/telegraf/telegraf.d "$@"
fi


# Check if the .credentials file exists
if [ -s "${FB_MONITOR_CRED_FILE}" ]; then
    echo "The freebox is registered, continuing the execution."

else
    echo "The Freebox isn't registered, registering. Please allow access using your freebox's panel."
    mkdir -p $( dirname "${FB_MONITOR_CRED_FILE}" )
    "${FB_MONITOR_BIN}" --register --config "${FB_MONITOR_CRED_FILE}" $FB_MONITOR_ARGS
fi


# required due to telegraf running under its own user
chgrp telegraf "${FB_MONITOR_CRED_FILE}"

    
# deactivate one or both of the output configurations
TARGET_CONF=/etc/telegraf/telegraf.d/output-influxdb.conf
if [ "${FB_TELEGRAF_OUTPUT/influx}" == "${FB_TELEGRAF_OUTPUT}" ]; then echo "Removing unused configuration: ${TARGET_CONF} ..."; rm -f "${TARGET_CONF}" ; fi

TARGET_CONF=/etc/telegraf/telegraf.d/output-prometheus.conf
if [ "${FB_TELEGRAF_OUTPUT/prometheus}" == "${FB_TELEGRAF_OUTPUT}" ]; then echo "Removing unused configuration: ${TARGET_CONF} ..."; rm -f "${TARGET_CONF}" ; fi


# redirect to the original entrypoint
echo "starting telegraf : '$@'"
exec /entrypoint.sh "$@"
