**freebox-monitoring**

# Dashboards

## Grafana

A dashboard is available for the following version of Grafana :

* [Dashboard for Grafana v9.x](dashboard_grafana_v9.json)  
  The plugin "natel-discrete-panel" v0.0.9 is required for the upper left panel, which can be deleted if desired.  
  More recent version of this plugin aren't official, and not correctly working.  

* [Dashboard for Grafana v11+](dashboard_grafana_v11.json)  
  No plugin requirement, the panel has been converted, but the native replacement is much less capable.  

To install the dashboard into Grafana, open the corresponding json file, and copy its content.  
Open Grafana, on the main menu from the left, under Dashboard, select Browse, then new, import, and paste the content of the json file, then save.  
In the same panel, you can also use the "upload json file" option if you have it locally.  
The new dashboard will be available under the name `Dashboard pour Freebox (Fibre) - API v4+`  

Next, open the new dashboard, under its settings, then variables, you must change the following variables :   
* dsdashboard : change the property "Instance name filter" with the correct name for your datasource in Grafana.  
  Currently set to `telegraf_network`
* dsinterval : change the property "values" by the frequency you have set in your monitory agent.  
  Currently set to `5m`

For both, check the "Preview" at the bottom, allowing to validate the result.  

Save, then refresh the page, and the panel will start presenting the data.


Please note the dashboards will provide a working sample, and a starting point to build one suitable to your own needs.  
On the other hand, they aren't made to cover every existing stat, which might be missing.  
