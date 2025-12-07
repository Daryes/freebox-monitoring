# Freebox-exporter Telegraf/InfluxDB
Also available on Docker-Hub (https://hub.docker.com/r/uzurka/freebox-telegraf)  
This work is based on Telegraf Docker image (https://hub.docker.com/_/telegraf),  
And on Bruno78's tuto about setting this up (https://www.nas-forum.com/forum/topic/66394-tuto-monitorer-sa-freebox-revolution/)

My goal is to be configured only with env variables.  
The entrypoint checks for the presence of the ``/usr/local/py/.credentials`` file. If the file is not present, it will automatically start the registration of the app on the freebox.  
In case of this registration fails, run ``docker exec -it container_name rm /usr/local/py/.credentials`` and restart the container to rerun the registration

#### Here's an exemple of what you can get using this container into grafana : 
![grafana](https://download.uzurka.fr/graf.png)

## Available Architectures
- amd64
- arm64 (aarch64)
- armv7 (arm)

## Common usage
Download docker-compose.yml file and edit it with your informations, then run ``docker-compose up -d``

## Configuration

### Exposed Ports

- 8125 StatsD
- 8092 UDP
- 8094 TCP  

### Environment variables
| Environment variable            | Exemple                                 | Usage                                                                                                                                                                                 |
|---------------------------------|-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TZ                              | CET                                     | Set your TimeZone into the container                                                                                                                                                  |
| INFLUXDB_URL                    | http://influxdb_container_hostname:port | Set the InfluxDB URL so the container can write metrics into it                                                                                                                       |
| INFLUXDB_DATABASE               | Freebox                                 | The name of the database Telegraf will write on                                                                                                                                       |
| INFLUXDB_SKIP_DATABASE_CREATION | True/False                              | True : The database will not attempt to be created by the telegraf container False : The database will be created by the telegraf container, using USERNAME & PASSWORD provided below |
| INFLUXDB_USERNAME               | freebox                                 | Username for the InfluxDB database                                                                                                                                                    |
| INFLUXDB_PASSWORD               | MyStrongP@ssw0rd!                       | Password used for the InfluxDB database                                                                                                                                               |
| ARGS                            | SPHDIWX4                                | See below                                                                                                                                                                             |
| TELEGRAF_AGENT_INTERVAL                            | 10s                                |defaults to 10s|
| TELEGRAF_SCRIPT_TIMEOUT                            | 5s                                |defaults to 5s|
### Arguments for freebox-exporter python script
This env is quite tricky, as i didn't found another way to get it variabilised, this is just the arguments used for executing the script into telegraf configuration.  
Here's the script.py -h, which tells you which arg is used for :  
| Argument | Description                                   |
|----------|-----------------------------------------------|
| S        | Get and show switch status                    |
| P        | Get and show switch ports stats               |
| H        | Get and show system status                    |
| D        | Get and show internal disk usage              |
| L        | Get and show LAN config                       |
| W        | Get and show wifi usage                       |
| I        | Get and show lan interfaces                   |
| X        | Get and show interfaces hosts                 |
| Y        | Get and show static dhcp                      |
| Z        | Get and show dynamic dhcp                     |
| 4        | Get and show 4G/lte xdsl aggregation counters |

The ARGS env come in the telegraf.conf rigt after the command ``/usr/local/py/freebox-monit.py -``, just select metrics you want and add choosen letters to the ARGS var
## Sources
- https://www.nas-forum.com/forum/topic/66394-tuto-monitorer-sa-freebox-revolution/
- https://hub.docker.com/r/repobazireinformatique/freebox-telegraf
