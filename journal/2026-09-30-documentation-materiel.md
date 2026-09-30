# Identification et repérage du matériel garage

Le mainteneur demande de documenter le matériel lié à l'article AliExpress
1005007964733966 et les boutons utiles au redémarrage. Le dépôt local
`garage-esp32` correspond au dépôt distant `killiankopp/garage-v2`.

Après `git fetch --prune origin`, `main` est alignée avec `origin/main`.
Les modifications préexistantes du README, de la documentation, des scripts
et de WebServerHandler sont conservées. Aucun firmware n'est compilé ou flashé.

La fiche AliExpress est inaccessible à l'outil navigateur par politique de
sécurité. Le lien est conservé sans paramètres d'affiliation. La description
fournie par le mainteneur conduit à la candidate LC Technology ESP32 Relay X2.
La fiche constructeur sert de source à deux images originales et au repérage
EN / IO0 ; la correspondance visuelle avec la carte installée reste à confirmer.
Les indications commerciales AC/DC, dimensions et CE ne sont pas présentées
comme des caractéristiques validées de l'installation.

La fiche `docs/HARDWARE.md`, les images et leur provenance sont liées depuis
le README. La procédure distingue appui physique, redémarrage effectif et
retour en service, avec lecture HTTP sans commande de porte.

Validation réalisée : liens Markdown locaux présents, deux JPEG lisibles
(750 × 1 552 et 750 × 874), empreintes SHA-256 identiques aux téléchargements,
absence d'espaces de fin de ligne dans les nouveaux documents et
`git diff --check` réussi. L'espace final préexistant dans un exemple du
README est conservé. Côté Amazone, `lat:check`, `graphify:update` et
`graphify:check` réussissent ; le graphe actualisé est le graphe AST.
Les tests firmware sont sans objet pour cette modification documentaire.
Aucun commit ni publication.

Le mainteneur fournit ensuite une URL directe AliExpress Media. L'image
est accessible dans Chrome et téléchargée dans son format AVIF original,
960 × 960, 62 490 octets. Elle montre deux variantes : une carte avec
transformateur jaune en haut et une carte DC en bas, tournée de 180°.
La fiche est corrigée pour indiquer EN en bas à gauche sur la première
et en haut à droite sur la seconde. Les JPEG constructeur restent identifiés
comme illustrations de la variante DC. Aucune déduction de plage secteur
ni de variante installée n'est faite à partir de la seule photo.

Le mainteneur confirme ensuite que la carte installée est **celle du haut,
avec transformateur jaune**. La fiche prend cette variante comme référence
principale, avec EN en bas à gauche dans l'orientation fournie. Les deux
JPEG de la variante DC sont relégués à la comparaison, pour ne pas transposer
leur plage d'alimentation à la carte réellement installée.

Validation finale après cette confirmation : les trois fichiers image sont
présents et leurs tailles et empreintes correspondent au manifeste ; l'AVIF
est bien en 960 × 960. Liens locaux, tableaux Markdown, espaces des nouveaux
documents et `git diff --check` passent. Les contrôles Amazone `lat:check`,
`graphify:update` et `graphify:check` passent également. À 10:50:34 CEST,
la sonde TCP depuis HA confirme le garage toujours absent, KRV_SS et le
service MQTT du Cerbo accessibles. Aucune commande de porte n'est envoyée.

Une seconde image AliExpress Media fournie par le mainteneur montre la variante
avec transformateur jaune seule, avec une légende numérotée : EN / reset au
repère 7 et IO0 au repère 6. Elle devient la vue principale de la fiche et les
README reprennent ces repères. L'original AVIF de 800 × 800, 34 028 octets,
est conservé sans retouche avec son URL et son empreinte SHA-256. L'entrée
90–250 V AC au repère 1 est attribuée à l'illustration commerciale ; elle
ne vaut pas vérification du câblage réel. Le montage initial reste disponible
pour comparaison. Aucun nouvel appui de reset ni contrôle réseau n'est réalisé
pendant cet ajout documentaire.

Après cet ajout, les quatre images correspondent au manifeste. Les liens
locaux, les tableaux, les repères EN/IO0 et `git diff --check` sont vérifiés ;
`npm run lat:check` et `npm run graphify:check` passent.

Après le redémarrage global rapporté par le mainteneur, la fiche matériel
est complétée avec le retour HA à 11:39:35 et les contrôles jusqu'à 11:44:10 :
bonne MAC sur `.134`, état API cohérent et 23/23 réponses `/health` lors
de la série de deux minutes. Le premier échec HTTP reste mentionné, ainsi
que l'impossibilité d'isoler la cause après une coupure commune.
