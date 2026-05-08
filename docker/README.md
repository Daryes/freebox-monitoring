# Freebox-exporter Telegraf/InfluxDB

Also available on Docker-Hub : (https://hub.docker.com/r/uzurka/freebox-telegraf)  
This work is based on [Telegraf Docker image](https://hub.docker.com/_/telegraf),  
on Bruno78's tuto about [setting this up](https://www.nas-forum.com/forum/topic/66394-tuto-monitorer-sa-freebox-revolution/),  
and [Uzurka](https://www.uzurka.fr/) initial Docker image.

The goal is to have the container configured only with env variables.  
The entrypoint checks for the presence of the `/data/.credentials` file (default location set by `FB_MONITOR_CRED_FILE`).  
If the file is not present, it will automatically start the registration of the app on the freebox.  
In case of this registration failing, run `docker exec -it container_name rm /data/.credentials` and restart the container to relaunch the registration.


## Available Architectures
The supported architectures are from [the image for Telegraf](https://hub.docker.com/_/telegraf)
- amd64
- arm64 (aarch64)
- armv7 (arm)


## Usage

### Build the image
Download or clone the repo, and run `docker-compose build`

### Common usage
As long the image is available locally, the repo it not required, only the 2 `docker-compose.*` files are.  
Edit the `docker-compose.env` to set the desired configuration.  
Also, the env file must be linked as `.env` using : `ln -s docker-compose.env .env`

When done, run `docker-compose up -d`

Notice : the credential/configuration file is set as `/data/.credentials` in the container, with a volume attached to /data.  
Also, mind the `pull_policy` active in the docker-compose.yml file, which will have to be removed when using a private image registry.


## Configuration

### Exposed Ports
- 9273 Prometheus


### Environment variables

They are documented in the `docker-compose.env` file.  
You will want to change the following settings : 
- FB_MONITOR_ARGS : the metrics to collect from the Freebox, see the next section for more informations.
- TELEGRAF_AGENT_INTERVAL : the collect frequency. The Freebox can have some difficulties to handle a lower value than "10s"
- FB_TELEGRAF_OUTPUT : the output plugin, either "influx" or "prometheus" or "influx:prometheus" for both

#### For influx :
- INFLUXDB_URL : the InfluxDB server url and port
- INFLUXDB_DATABASE : the database name
- INFLUXDB_USERNAME & INFLUXDB_PASSWORD : the user/password for accessing the DB. It must have write access.

#### For prometheus :
- DOCKER_HOST_IP : change it to `0.0.0.0` to allow an external access. The default is set to localhost.
- PROMETHEUS_BASIC_USERNAME & PROMETHEUS_BASIC_PASSWORD : the user/password known by the Prometheus server to access Telegraf
- PROMETHEUS_IP_RANGE : IP addresses and/or ranges allowed to access Telegraf. The default allows any IP address.


### Arguments for freebox-exporter python script

The environment variable `FB_MONITOR_ARGS` allows to reuse any parameter for the script `freebox_monitor.py`  
See the "Command-line arguments" section in the [readme](../README.md)

Be mindful when using quotes, while they should work, having multiple variable interpolations can lead to unexpected results.  
When possible, prefer single-quotes instead of doubles.



## Sources
- https://www.nas-forum.com/forum/topic/66394-tuto-monitorer-sa-freebox-revolution/
- https://hub.docker.com/r/repobazireinformatique/freebox-telegraf
