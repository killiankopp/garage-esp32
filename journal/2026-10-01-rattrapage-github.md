# Publication des travaux Garage

Le rattrapage publie la route /gate/pulse preparee localement, sa protection
par le middleware existant, la correction des URL Keycloak sans /auth et
la documentation materielle du 30 septembre avec provenance des images.
La route envoie une seule impulsion sans deduire une direction ; la reponse
reste l'etat observe. Les autres routes et modes d'authentification restent
compatibles. Les exemples de configuration ne contiennent aucun secret reel.

Validation : build PlatformIO ESP32, 17 tests natifs existants, deux regressions
C++ executees depuis Python sur le vrai corps du handler pulse avec doubles
des frontieres (refus sans relais, acceptation avec une impulsion et etat
observe conserve), compilation Python du script Keycloak, images/manifeste,
liens locaux et git diff --check. Le build complet valide la traduction Arduino ;
le harnais ne pretend pas tester un serveur JWT ni un moteur de porte.

Aucun firmware n'est flashe. Le depot n'a pas de workflow release configure ;
le binaire local n'est ni un package publie ni une preuve du firmware installe.
Retour arriere : revert de la PR ; les sauvegardes locales restent privees.

Les trois caches Python suivis par erreur sont retires de Git et ignores.
La compilation et les tests ne doivent pas republier de bytecode local.
