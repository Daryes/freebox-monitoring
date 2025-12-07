# versions: https://hub.docker.com/_/telegraf
FROM telegraf:1.27.4

ENV TELEGRAF_AGENT_INTERVAL=1m
ENV TELEGRAF_SCRIPT_TIMEOUT=15s


# Install required packages
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg-agent \
        software-properties-common \
        python3-distutils \
        python3-pip \
        python-is-python3 \
    && apt-get autoremove -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*;


# install fbmonitor python requirements
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt  \
    && rm /tmp/requirements.txt


# add script and cert files
RUN mkdir -p /data /usr/local/py/
COPY docker/entrypoint-fbm.sh  /
COPY docker/telegraf/telegraf.conf  /etc/telegraf/
COPY docker/telegraf/telegraf.d  /etc/telegraf/telegraf.d
COPY ssl  /usr/local/py/ssl
COPY freebox_monitor.py  /usr/local/py/

# not using buildx
RUN chmod +x /entrypoint-fbm.sh   /usr/local/py/freebox_monitor.py


ENTRYPOINT ["/entrypoint-fbm.sh"]

# source: https://git.uzurka.fr/Uzurka/freebox-exporter-telegraf/