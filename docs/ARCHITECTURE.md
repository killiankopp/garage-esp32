# Architecture du Projet Garage V2

## Vue d'ensemble

Ce projet a été refactorisé en suivant le principe de responsabilité unique (SRP) et d'autres bonnes pratiques de développement. Le code est maintenant organisé en composants modulaires et réutilisables.

## Structure des Composants

### 1. Config.h
- **Responsabilité** : Centraliser toutes les constantes de configuration
- **Contenu** : 
  - Définitions des pins hardware
  - Timeouts et délais
  - Configuration du serveur

### 2. GateTypes.h
- **Responsabilité** : Définir les types et énumérations partagés
- **Contenu** : 
  - `GateState` (CLOSED, OPEN, UNKNOWN)
  - `OperationState` (IDLE, OPENING, CLOSING)

### 3. WiFiManager
- **Responsabilité** : Gérer la connexion WiFi
- **Fonctionnalités** :
  - Initialisation de la connexion
  - Vérification du statut
  - Récupération de l'IP locale

### 4. GateController
- **Responsabilité** : Contrôler le hardware du portail
- **Fonctionnalités** :
  - Configuration des pins
  - Lecture des capteurs
  - Activation du relais
  - Détection de l'état du portail

### 5. GateMonitor
- **Responsabilité** : Surveiller et gérer les états du portail
- **Fonctionnalités** :
  - Surveillance des changements d'état
  - Gestion des timeouts d'opération
  - Système d'auto-fermeture
  - Gestion des alertes
  - Suivi des opérations en cours

### 6. WebServerHandler
- **Responsabilité** : Gérer le serveur web et les APIs
- **Fonctionnalités** :
  - Gestion des routes HTTP
  - Génération des réponses JSON
  - Interface REST pour le contrôle du portail

## Avantages de cette Architecture

### Principe de Responsabilité Unique (SRP)
- Chaque classe a une seule raison de changer
- Code plus maintenable et testable
- Séparation claire des préoccupations

### Faible Couplage
- Les composants communiquent via des interfaces claires
- Facilite les tests unitaires
- Permet la réutilisation des composants

### Haute Cohésion
- Fonctionnalités liées regroupées dans le même module
- Code plus lisible et compréhensible

### Extensibilité
- Facile d'ajouter de nouvelles fonctionnalités
- Possibilité d'ajouter de nouveaux types d'alertes
- Support facile pour de nouveaux protocoles de communication

## Flux d'Exécution

1. **Initialisation** (`setup()`)
   - Configuration du hardware (GateController)
   - Connexion WiFi (WiFiManager)
   - Initialisation du monitoring (GateMonitor)
   - Démarrage du serveur web (WebServerHandler)

2. **Boucle Principale** (`loop()`)
   - Traitement des requêtes web
   - Mise à jour du monitoring
   - Gestion des timeouts et auto-fermeture

## Configuration WiFi

Le projet utilise les variables d'environnement pour la configuration WiFi :
```bash
export WIFI_SSID="YourSSID"
export WIFI_PASSWORD="YourPassword"
pio run
```

## API Endpoints

- `GET /` - Status général
- `GET /health` - Vérification de santé
- `GET /gate/status` - État détaillé du portail (JSON)
- `POST /gate/open` - Demander une ouverture selon l'etat capteur
- `POST /gate/close` - Demander une fermeture selon l'etat capteur
- `POST /gate/pulse` - Envoyer une impulsion relais sans deduire de direction

## Exemple de Réponse JSON

```json
{
  "status": "open",
  "sensor_closed": false,
  "sensor_open": true,
  "alert_active": false,
  "auto_close_enabled": true,
  "auto_close_remaining": 165000
}
```
