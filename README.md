# 🚪 Garage V2 - Smart Gate Controller

Contrôleur intelligent de portail basé sur ESP32 avec API REST, surveillance de position, timeouts et fermeture automatique.

## 🚀 Flash

```sh
./scripts/vscode_build.sh flashs
```

## � Démarrage rapide

### 1. Configuration

Créez un fichier `.env` à la racine :

```bash
WIFI_SSID=VotreSSID
WIFI_PASSWORD=VotrePassword
KEYCLOAK_SERVER_URL=https://your-keycloak-server
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
EMQX_BROKER_HOST=emqx.amazone.lan
EMQX_BROKER_PORT=1883
EMQX_USERNAME=
EMQX_PASSWORD=
EMQX_TOPIC=garage/authorized
EMQX_UNAUTHORIZED_TOPIC=garage/unauthorized
```

### 2. Compilation et upload

```bash
# Compiler et uploader sur l'ESP32
./scripts/build.sh flash

# Ou étape par étape :
./scripts/build.sh build     # Compiler seulement
./scripts/build.sh upload    # Uploader sur l'ESP32
./scripts/build.sh monitor   # Monitorer la sortie série
```

### 3. Scripts disponibles

| Script | Description |
|--------|-------------|
| `./scripts/build.sh` | Script principal de build avec PlatformIO CLI |
| `./scripts/vscode_build.sh` | Script optimisé pour VS Code |
| `./scripts/run_tests.sh` | Lancement des tests unitaires |

### 4. Tests

```bash
# Lancer tous les tests
./scripts/build.sh test

# Tests spécifiques
pio test -e native
```

#### Vérifier Keycloak avant flash

```bash
source scripts/load_env.sh
python3 scripts/test_keycloak.py
```

Options utiles :

- `--token <jeton>` : fournir un token existant à introspecter
- `--skip-introspection` : ne faire que la récupération du token
- `--insecure` : ignorer la vérification TLS (environnement de dev uniquement)

## �🔧 Fonctionnalités

- **Contrôle du portail** via API REST (ouverture/fermeture)
- **Détection de position** avec 2 capteurs (ouvert/fermé)
- **Surveillance des timeouts** (15 secondes par défaut)
- **Fermeture automatique** après 3 minutes d'ouverture
- **Système d'alertes** en cas de dysfonctionnement
- **API JSON unifiée** pour tous les retours
- **Authentification JWT** avec Keycloak
- **Logging Kafka** pour la surveillance

## 🛠 Configuration matérielle

La [fiche matériel et redémarrage](docs/HARDWARE.md) contient le lien d'achat,
la vue légendée de la **carte installée, avec transformateur jaune**.
Elle distingue **EN (reset, repère 7, bouton inférieur gauche)** de
**IO0 (programmation, repère 6, juste au-dessus)** dans l'orientation fournie.
Les photos constructeur d'une autre variante DC sont conservées comme
comparaison, sans en transposer les caractéristiques d'alimentation.

### Connexions ESP32

| Composant | Pin ESP32 | Description |
|-----------|-----------|-------------|
| Relais 1 | GPIO 16 | Commande du portail |
| Capteur fermé | GPIO 18 | Détection position fermée |
| Capteur ouvert | GPIO 19 | Détection position ouverte |

### Câblage des capteurs

```text
Capteur "FERMÉ":
├─ Une borne → GPIO 18
└─ Autre borne → GND

Capteur "OUVERT":  
├─ Une borne → GPIO 19
└─ Autre borne → GND
```

**Note**: Les capteurs utilisent les résistances pull-up internes de l'ESP32. Pas de composants supplémentaires nécessaires.

## 🌐 API REST

Toutes les routes retournent du JSON avec le même format.

### Routes disponibles

| Route | Méthode | Description |
|-------|---------|-------------|
| `/` | GET | Status de base |
| `/health` | GET | Health check |
| `/gate/open` | GET | Demander une ouverture selon l'etat capteur |
| `/gate/close` | GET | Demander une fermeture selon l'etat capteur |
| `/gate/pulse` | GET | Envoyer une impulsion relais sans deduire de direction |
| `/gate/status` | GET | État détaillé du portail |

### Status possibles

| Status | Description |
|--------|-------------|
| `closed` | Portail fermé (capteur fermé activé) |
| `open` | Portail ouvert (capteur ouvert activé) |
| `opening` | **Opération d'ouverture en cours** |
| `closing` | **Opération de fermeture en cours** |
| `unknown` | Position indéterminée (aucun capteur ou les deux) |

## 📋 Exemples de réponses

### Portail fermé au repos

```json
{
  "status": "closed",
  "sensor_closed": true,
  "sensor_open": false,
  "alert_active": false,
  "auto_close_enabled": false
}
```

### Pendant une ouverture

```json
{
  "status": "opening",
  "sensor_closed": false,
  "sensor_open": false,
  "operation_time": 3500,
  "timeout_remaining": 11500,
  "alert_active": false,
  "auto_close_enabled": false
}
```

### Portail ouvert avec auto-fermeture

```json
{
  "status": "open",
  "sensor_closed": false,
  "sensor_open": true,
  "alert_active": false,
  "auto_close_enabled": true,
  "auto_close_time": 45000,
  "auto_close_remaining": 135000
}
```

### Pendant une fermeture

```json
{
  "status": "closing",
  "sensor_closed": false,
  "sensor_open": false,
  "operation_time": 2100,
  "timeout_remaining": 12900,
  "alert_active": false,
  "auto_close_enabled": false
}
```

### Position indéterminée

```json
{
  "status": "unknown",
  "sensor_closed": false,
  "sensor_open": false,
  "alert_active": false,
  "auto_close_enabled": false
}
```

### Timeout d'opération (alerte)

```json
{
  "status": "opening",
  "sensor_closed": false,
  "sensor_open": false,
  "operation_time": 15000,
  "timeout_remaining": 0,
  "alert_active": true,
  "auto_close_enabled": false
}
```

### Portail déjà ouvert (commande ignorée)

```json
{
  "status": "open",
  "sensor_closed": false,
  "sensor_open": true,
  "alert_active": false,
  "auto_close_enabled": true,
  "auto_close_time": 120000,
  "auto_close_remaining": 60000
}
```

## ⚙️ Configuration des timeouts

Modifiables dans le code source :

```cpp
const unsigned long OPENING_TIMEOUT = 15000;   // 15 secondes pour ouvrir
const unsigned long CLOSING_TIMEOUT = 15000;   // 15 secondes pour fermer
const unsigned long AUTO_CLOSE_DELAY = 180000; // 3 minutes auto-fermeture
```

## 🔒 Configuration WiFi sécurisée

### ⚠️ Important

Le fichier `platformio.ini` est versionné sur Git, donc **JAMAIS de secrets dedans !**

### Configuration

1. **Créez le fichier `.env`** à la racine du projet (ignoré par Git) :

```env
WIFI_SSID=VotreSSID
WIFI_PASSWORD=VotreMotDePasse
```

1. **Utilisez le script de build** qui charge automatiquement le `.env` :

```bash
# Compilation
./build.sh

# Upload vers ESP32
./build.sh upload

# Upload + monitoring
./build.sh monitor
```

### Alternative manuelle

```bash
export WIFI_SSID="VotreSSID"
export WIFI_PASSWORD="VotreMotDePasse"
pio run --target upload
```

## 🚀 Build et déploiement

```bash
# Compiler
pio run

# Uploader sur l'ESP32
pio run --target upload

# Monitorer la sortie série
pio device monitor
```

## � Organisation du projet

```text
garage-v2/
├── src/                     # Code source ESP32
│   ├── main.cpp
│   └── components/          # Modules du projet
├── test/                    # Tests unitaires
├── scripts/                 # Scripts de build et outils
│   ├── build.sh            # Script principal
│   ├── vscode_build.sh     # Script pour VS Code
│   └── run_tests.sh        # Tests
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # Architecture du projet
│   ├── AUTHENTICATION.md   # Système d'auth
│   └── KAFKA_*.md         # Documentation Kafka
├── platformio.ini          # Configuration PlatformIO
└── .env                   # Variables d'environnement (local)
```

## �🔐 Sécurité

- ✅ Le fichier `.env` est dans `.gitignore`
- ✅ Aucun secret dans le code versionné
- ✅ Variables d'environnement chargées dynamiquement
- ✅ Vos secrets ne seront jamais exposés sur GitHub

## 📱 Utilisation

### Exemples d'appels API

```bash
# Status du portail
curl http://[IP_ESP32]/gate/status

# Envoyer une impulsion relais
curl http://[IP_ESP32]/gate/pulse
```

### Comportements automatiques

1. **Fermeture automatique** : Si le portail reste ouvert 3 minutes, il se ferme automatiquement
2. **Surveillance des timeouts** : Alerte si une opération dépasse 15 secondes
3. **Prévention des actions inutiles** : Ignore les commandes si déjà dans l'état souhaité

## 🐛 Débogage

Consultez la sortie série pour le monitoring :

- Changements d'état détectés
- Démarrage des opérations
- Déclenchement des timeouts
- Alertes système
