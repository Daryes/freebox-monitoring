# freebox-monitoring
Simple Freebox Monitoring for anything able to load data in Influxdb or Graphite format.

Forked from [freebox-revolution-monitoring](https://github.com/tsugliani/freebox-revolution-monitoring)

![freebox monitoring dashboard](doc/freebox_dashboard.png)

Based/Inspired by https://github.com/tuxtof/freebox-monitoring

The newer freebox devices don't offer the hosted file with all the data information usually accessible here [`http://mafreebox.freebox.fr/pub/fbx_info.txt`](http://mafreebox.freebox.fr/pub/fbx_info.txt)

This solution is leveraging the [Freebox API](http://dev.freebox.fr/sdk/os/) for most of the data available, but some might be missing, due to lack of hardware or internet.  
If you want to extend the script, check the official API documentation [on the dedicated page](http://dev.freebox.fr/sdk/os/connection/).  
The debug mode can also be activated to print the retrieved data from the API.


## Documentation

* **[Changelog](CHANGELOG.md)**
* **[Installation](doc/installation.md)**
* **[Dashboard](doc/dashboard.md)**
* **[List of available metrics and tags](doc/output_metrics.md)**


## Command-line arguments

Available command-line switches and parameters:

```
SexiMonitor (0.9.0)

options:
  -h, --help            show this help message and exit
  -d, --debug           Activate the debug mode and print the retrieved data
  -c /path/to/file, --config /path/to/file
                        Full path to the credential file. Default is: <current directory>/.credentials
  -r, --register        Register the app with the Freebox API and cache the API url and version
  -s, --register-status
                        Get the registration status
  -f {graphite,influxdb}, --format {graphite,influxdb}
                        Specify output format between 'graphite' and 'influxdb'. Default is: graphite
  -e target-box, --endpoint target-box
                        Specify the dns or ip of the box API endpoint. Default is: mafreebox.freebox.fr
  --auth-hash-type sha1|sha256|sha3_256|...
                        Select the hash algorithm used when opening a session at the challenge step. Refer to hashlib documentation and the freebox API object SessionStart from /login/authorize for the
                        supported types. Default is: sha1
  --api-endpoint-detect-force
                        Ignore the cache and force the detection of the api capabilities and version from the endpoint target. Allow some overrides.
  --api-endpoint-detect-ssl-domain
                        Use 'api_domain' and 'https_port' from the API response to detect the https URL. Not using this parameter will keep for SSL the url : https://mafreebox.freebox.fr
  --api-version-force version_major
                        Override the API major version. Must be used with either '--register' or '--api-endpoint-detect-force'
  --ssl-no-verify       Disable the certificate validity test on ssl connections
  --ssl-ca-bundle-file /path/to/file.pem
                        Full path to the custom ssl CA bundle file in PEM format. Both the root and intermediate certs must be in the bundle. Default is: /server/freebox/releases/freebox-
                        monitoring-v0.9.0b6/ssl/free_telecom_bundle.pem
  -v, --version         Show the version and exit
  -C, --status-call     Get the phone call logs and history
  -X, --status-dhcp     Get and show the dhcp status
  -D, --status-disk, --internal-disk-usage
                        Get and show the disks status
  -B, --status-lan-browser
                        Get and show the hosts on the local network with the lan browser
  -L, --status-lte      Get and show 4G/LTE aggregation status
  -H, --status-sys      Get and show system status
  -P, --status-ports    DEPRECATED: has no effect, integrated into --status-switch and kept for compatibility
  -S, --status-switch   Get and show the switch and ports status
  -M, --status-virtualmachines
                        Get and show the virtual machines status
  -V, --status-vpnsrv   Get and show the VPN Servers status
  -Z, --status-vpnclient
                        Get and show the integrated VPN client status
  -W, --status-wifi     Get and show the Wifi status
  --patch-rate-up-bytes-up
                        Fix the rate_up & bytes_up metrics which are cumulated with their *_down counterpart since 10/2024. See task 40445 for more information. 
                        This requires the '--status-switch' parameter to be activated, and the freebox switch not used for LAN traffic aside for internet access
```

**Notice:** using the parameter `--status-virtualmachines` on a system missing the virtualization capability will cause a 404 error.  
Also, the following parameters have not been fully tested and could not work completely: --status-virtualmachines, --status-vpnsrv, --status-lte, --status-disk


## Authors

* [Tuxtof : original idea](https://github.com/tuxtof/freebox-monitoring)
* [Tsugliani : author of SexyMonitor](https://github.com/tsugliani/freebox-revolution-monitoring)
* [Bruno78310 : alternative fork - docker implementation](https://github.com/bruno78310/Freebox-Revolution-Monitoring)
* [Uzurka : continuity of Bruno78310's and docker ameliorations](https://git.uzurka.fr/Uzurka/freebox-exporter-telegraf)
* [Ogme : current maintainer](https://github.com/Daryes/freebox-monitoring)

## Licence

[MIT](LICENSE)