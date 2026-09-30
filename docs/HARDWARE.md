# Matériel du garage : ESP32-WROOM à deux relais

Cette fiche réunit la référence d'achat, les photos de repérage et la procédure de redémarrage du contrôleur. Elle distingue la carte physique, le firmware du dépôt et son état réellement installé.

## Identification et sources

Le matériel installé, confirmé visuellement par le mainteneur le 30 septembre 2026, est la **carte du haut de l'image de l'annonce : module à deux relais avec ESP32-WROOM et transformateur jaune**.

| Référence | Information |
| --- | --- |
| Fiche d'achat | [AliExpress — article 1005007964733966](https://fr.aliexpress.com/item/1005007964733966.html) |
| Nom fourni par le mainteneur | Module de relais double canal avec ESP32-WROOM, Wi-Fi et Bluetooth |
| Variante installée | **Carte du haut, avec transformateur jaune et bornier d'alimentation à deux vis** |
| Marquage visible sur l'image | `LC` ; référence complète et révision de la carte réelle non relevées |
| Illustrations de l'annonce fournies directement | Une vue légendée de la variante installée ; un montage de deux cartes distinctes pour comparaison |
| Alimentation indiquée sur la vue légendée | **90–250 V AC**, repère **1**, selon l'illustration du vendeur ; tension réellement câblée non relevée |
| État d'identification | **Variante visuelle confirmée par le mainteneur** ; tension réellement câblée non relevée |

Le lien d'achat est conservé sans ses paramètres d'affiliation. La page produit a été bloquée par la politique de sécurité de l'outil navigateur. Le mainteneur a fourni directement les URL de deux images de l'annonce : elles sont accessibles et conservées localement. Les deux autres illustrations viennent de la fiche **constructeur** de la variante DC.

La description commerciale transmise mentionne à la fois DC 5–60 V et AC 90–250 V. L'image montre deux variantes, et non deux vues de la même carte. Les caractéristiques de la variante DC sans transformateur jaune ne sont pas transposées à la carte installée. Ne pas utiliser une indication de tension des contacts des relais comme tension d'alimentation de la carte. Dimensions, poids et conformité CE du descriptif commercial ne sont pas validés dans cette fiche.

## Photos et repérage des boutons

Les images originales sont conservées localement, avec leur [provenance](images/esp32-relay-x2/SOURCES.md). Le repérage d'usage ci-dessous concerne uniquement la variante avec transformateur jaune, confirmée comme installée.

### Carte installée : variante avec transformateur jaune

Cette vue légendée fournie par le mainteneur devient la référence de repérage. Elle montre la même variante que la carte du haut du [montage initial](images/esp32-relay-x2/annonce-deux-variantes.avif), confirmée comme installée. Les numéros et leur légende appartiennent à l'image originale du vendeur.

![Variante avec transformateur jaune : EN Reset au repère 7, IO0 au repère 6](images/esp32-relay-x2/carte-installee-reperes-annonce.avif)

| Bouton de la carte installée | Position sur la vue légendée | Fonction |
| --- | --- | --- |
| **EN — repère 7** | **Bouton inférieur gauche, près du trou de fixation** | **Reset : redémarre l'ESP32** |
| **IO0 — repère 6** | Bouton juste au-dessus de EN | Entrée programmable et sélection du mode de téléchargement au démarrage ; ne pas l'utiliser pour un simple reset |

**Orientation : ESP32 à gauche, relais bleus à droite, transformateur jaune en bas au centre.** Toujours lire **EN** sur la carte : « le bouton du bas » ne vaut que pour cette orientation.

### Autre variante : comparaison uniquement

La carte du bas du [montage initial](images/esp32-relay-x2/annonce-deux-variantes.avif) n'est **pas** la variante installée : elle n'a pas le transformateur jaune et possède un bornier à trois vis `VCC / GND / 5V`. Elle est tournée de 180° ; son bouton EN apparaît donc en haut à droite.

Les photos [repérage constructeur DC](images/esp32-relay-x2/reperage-boutons-constructeur.jpg) et [présentation constructeur DC](images/esp32-relay-x2/presentation-constructeur.jpg) sont conservées pour la traçabilité de l'identification. Elles proviennent de la [fiche LC Technology DC5-60V Power Supply Dual WiFi Bluetooth Relay Module](http://www.chinalctech.com/cpzx/Programmer/Relay_Module/518.html) et ne décrivent pas l'étage d'alimentation de la carte installée.

La référence générique `esp32doit-devkit-v1` de PlatformIO est une cible de compilation ; elle ne prouve pas que le matériel installé soit une carte DevKit avec USB.

## Redémarrer uniquement le contrôleur

Le mainteneur indique qu'une coupure d'alimentation couperait aussi le point d'accès Wi-Fi et le moteur. Utiliser le bouton de reset identifié permet de garder ces autres équipements alimentés. Une action sur un bouton exposé reste à réaliser sur place, sans approcher de bornes électriques sous tension.

1. Vérifier que la carte correspond à la photo et identifier **EN, repère 7**. En cas de marquage différent ou illisible, arrêter le repérage avant tout appui.
2. Garder la porte immobile, le passage dégagé et le moyen manuel de commande disponible. Prévenir la personne qui observe les échanges réseau.
3. Appuyer brièvement **une seule fois sur EN**, puis relâcher, sans maintenir IO0 et sans déplacer de cavalier.
4. Noter l'heure et ce qui se produit : voyants, éventuel clic de relais, éventuel mouvement. L'absence de changement visible ne prouve ni un échec ni un succès du redémarrage.
5. Vérifier le retour réseau et applicatif : association au Wi-Fi, adresse IP, réponse de `/health`, puis état frais dans Home Assistant. Attendre jusqu'à une minute pour ce premier contrôle.
6. Si le contrôleur reste absent, conserver le constat et passer au diagnostic local du démarrage ; ne pas enchaîner les resets ou les impulsions de porte.

Un retour du réseau ne prouve pas à lui seul la fiabilité des capteurs ni la résolution durable de la panne. Les routes de commande `/gate/open`, `/gate/close` et `/gate/pulse` ne sont jamais des sondes de disponibilité.

## Connexions utilisées par le firmware du dépôt

Les broches ci-dessous proviennent de `src/components/Config.h` et de la documentation du firmware. Elles doivent être confrontées au câblage réel avant une modification matérielle.

| Usage | Broche |
| --- | --- |
| Relais de commande de la porte | GPIO16 |
| Capteur de position fermée | GPIO18 |
| Capteur de position ouverte | GPIO19 |

L'image de la carte installée montre une rangée de connexions près des boutons et ne montre pas de prise USB. Cette fiche ne constitue pas une procédure de branchement USB/TTL ni de flash ; le brochage exact doit être vérifié avant tout raccordement. Aucune mise à jour du firmware n'a été effectuée pendant le repérage.

## État du diagnostic au 30 septembre 2026

Le mainteneur confirme un appui présenté comme un reset, sans changement visible. À 10:32:37 puis 10:40:07 CEST, le contrôleur reste injoignable à l'adresse attendue `10.0.0.134`, alors que le point d'accès et le Cerbo répondent. Le contrôle depuis HA à 10:50:34 confirme un timeout TCP/80 du garage, avec TCP/80 de KRV_SS et TCP/1883 du Cerbo accessibles. Le bouton exact actionné et le redémarrage effectif ne sont pas encore confirmés. Il faut donc conserver séparément la preuve du geste et celle du retour en service.

**Retour en service après coupure commune du Wi-Fi et de l'ESP, ensuite rapportée par le mainteneur :** HA retrouve un état `closed` à 11:38:59, connaît une brève indisponibilité, puis revient à `closed` à 11:39:35. À 11:41, la MAC attendue répond sur `10.0.0.134` et `/gate/status` indique `sensor_closed=true`, `sensor_open=false`. Une première lecture `/health` échoue ; la série distincte de 11:42:10 à 11:44:10 obtient ensuite 23/23 réponses HTTP 200 `OK`. Aucun mouvement de porte n'est commandé pendant ces vérifications. La remise en service est confirmée ; ce redémarrage simultané ne permet pas d'isoler la cause ni de conclure à une fiabilité durable.
