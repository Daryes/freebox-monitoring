# freebox-monitoring changelog


## v0.7.0
* implémentation des tags en sortie par groupe de métriques au format influxdb et graphite
* refonte des métriques switch_* pour utiliser les tags. Exemple : switch_1_tx_bytes_rate=value => tag(switch_port=1) switch_tx_bytes_rate=value


## v0.6.2
* ligne de commande:
  * nouveau parametre: --api-version-force pour specifier la version à utiliser de l'API. Doit etre utilisé avec `--register` ou `--api-endpoint-detect-force`


## v0.6.1
* creation du fichier changelog
* ajout de tags en global: api_endpoint, api_version
* ligne de commande:
  * nouveau parametre: --endpoint pour specifier le serveur cible, par defaut : "mafreebox.freebox.fr"
  * nouveau parametre: --version
  * nouveau parametre: --config pour specifier le fichier credential, par defaut : "./.credentials"


## v0.6.0
* support de l'acces a l'API en https. Le parametre `--ssl-no-verify` doit etre utilisé pour le moment.
* detection automatique de l'usage de SSL pour l'accès à l'API
* detection automatique de la version de l'API
* mise en cache du endpoint et de la version de l'api
* support de tags en global sur les metriques influxdb et graphite
* ajout de tags "hw_*" en global si les metriques system sont actives
* simplification des fonctions d'appel à l'API
* simplification de la recuperation des metriques xDSL
* detection automatique du nombre de port du switch
* correction de certains messages d'information
* ligne de commande:
  * nouveau parametre: --debug pour le mode debug, permet d'afficher un dump des reponses de l'API
  * nouveau parametre: --ssl-no-verify pour ignorer la verification du certificat SSL de la box
  * nouveau parametre: --api-endpoint-detect-force pour ignorer le cache et constamment détecter la version et le mode d'accès à l'API
  * parametre modifié: --format restreint aux valeurs "graphite" et "influxdb"
  * parametre ignoré: --status-ports intégré au paramètre --status-switch, conservé pour la compatibilité
* nouvelles metriques:
  * systeme: "box_authenticated"


## v0.5.1
* correction de la recuperation de la metrique systeme "uptime_val" si absente


## v0.5.0
* correction des metriques sytemes
* refonte de la gestion des parametres app_id, app_name et device_name
* normaliztion des paramètre pour la ligne de commande

## v0.4.5 - 2022
* fork
* ajout de metriques supplementaires pour FFTH
* correction des metriques switch => ports ayant été renommées
* correction du format d'affichage pour influxdb
* corrections spécifique à Python3



## v0.4.4 - 13/12/2018
Version orginelle de [TSugliani](https://github.com/tsugliani/freebox-revolution-monitoring)