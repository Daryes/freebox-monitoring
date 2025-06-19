# freebox-monitoring changelog


## v0.8.0
* modification des métriques avec changement de nom de la mesure principale, exception des metriques par défaut hors paramètre `--status-...`
  * pour influxdb : passage de `freebox` à `freebox_<type>`
  * pour graphite : passage de `freebox` à `freebox.<type>`
* parametre --register-status : seul les 4 premiers caractères du token sont affichés
* metriques lan browser : tags normalisés en lan_* pour limiter les conflits (tag "host" par exemple)
* metriques wifi : tags normalisés en wifi_* pour limiter les conflits
* metriques dhcp : metriques texte déplacées en tags
* documentation : création de la liste des metriques et tags générés
* API en https : support complet avec utilisation du certificat custom de Free Telecom. Le paramètre `--ssl-no-verify` n'est plus obligatoire.
* register-status: affichage du chemin du fichier de configuration/credential utilisé
* metriques wifi_station_* et diskfs_* : reorganisation de l'ordre de certains tags pour cohérence, ne devrait pas avoir d'impact.
* tag global : le tag `api_endpoint` contient à présent l'url complete avec la version de l'api
* metriques principales : ajout des champs config_* pour le ping, adblock, wol, sip_alg, remote et api_remote.
* metriques switch : ajout de la metrique calculée `client_last_seen` avec en tags leur nom et adresse mac des clients connus de chaque port du switch.
* ligne de commande :
  * nouveau parametre : `--ssl-ca-bundle-file` permettant de redefinir le fichier de certificats CA bundle
  * nouveau parametre : `--status-vpnsrv` pour les métriques des serveurs VPN
  * nouveau parametre : `--status-vpnclient` pour les métriques du client VPN intégré


## v0.7.3
Non diffusé.  
* correction format de sortie pour compatibilité avec influxdb v1
* retrait de la date/heure inutile pour le format de sortie influxdb
* ajout d'autres caractères retirés pour les valeurs de tags tels que "vendor"
* metriques system : correction de la detection API v8+ et v8-
* metrique sys : correction de sys_authenticated en 0 ou 1 au lieu de booleen
* metrique wifi : correction d'erreur si utilisé lorsque le wifi de la box est désactivé
* tag global : retrait de `hw_operator`, remplacé par `net_operator` via "--status-sys"
* metriques wan_ipv4* et wan_ipv6* : ajout de valeurs par defaut en cas d'absence de connexion
* metriques connection : ajout du tag `conn_media`
* metriques lan : ajout du champ `first_activity`
* ligne de commande :
  * nouveau parametre : `--patch-rate-up-bytes-up` pour corriger les metriques rate_up et bytes_up cumulées avec leur équivalents *_down


## v0.7.2
* ajout des metriques pour le wifi
* ligne de commande:
  * nouveau parametre: `--status-call` pour les appels téléphoniques
  * nouveau parametre: `--status-wifi` pour le wifi
  * nouveau parametre: `--status-lte` pour la connexion LTE
  * nouveau parametre: `--status-lan-browser` pour les informations sur les clients environnants
* modification des tags "*_id" : le suffixe "_id" est retiré du nom pour chaque tag principal (id de disque, id de partition, id de reseau, ...)


## v0.7.1
* Mise à jour pour API v13
  * Utilisation de tags
  * refonte des métriques disk_* et partition_*
  * refonte des métriques cpu_temp et fan_rpm
* parametre `--status-disk` ajouté en alias pour `--internal-disk-usage`
* certains tags dont sfp_vendor et lan_vendor sont nettoyés de leur caractères speciaux,  
  et peuvent différer légèrement des informations vues par la freebox.


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