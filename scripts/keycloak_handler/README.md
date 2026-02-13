# Scripts Keycloak

## keycloak_00_init.py

Script d'initialisation automatisé de Keycloak pour créer un administrateur permanent et supprimer le compte admin temporaire.

### Prérequis

1. **Python 3.6+** installé
2. **kubectl** configuré avec accès au cluster
3. **Keycloak** déployé et accessible à `http://keycloak.amazone.lan`
4. **Vault** déployé dans le namespace `security`

### Installation des dépendances

```bash
cd scripts
pip install -r requirements.txt
```

Ou avec un environnement virtuel :

```bash
cd scripts
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Utilisation

```bash
cd scripts
python3 keycloak_00_init.py
```

Ou directement :

```bash
./scripts/keycloak_00_init.py
```

### Fonctionnalités

Le script effectue automatiquement les opérations suivantes :

1. ✅ **Récupération du mot de passe admin temporaire** depuis Kubernetes secret
2. ✅ **Connexion à Keycloak** avec le compte admin temporaire
3. ✅ **Création de l'utilisateur permanent** `killian` avec un mot de passe sécurisé
4. ✅ **Attribution de tous les rôles administrateurs** :
   - Rôles realm-level (admin, create-realm, etc.)
   - Rôles client realm-management (realm-admin, manage-users, etc.)
   - Rôles client master-realm
   - Rôles client account
5. ✅ **Vérification complète des permissions** avant suppression
6. ✅ **Suppression du compte admin temporaire** après validation
7. ✅ **Sauvegarde des credentials dans Vault** à `secret/keycloak/admin-permanent`

### Sécurité

- ✅ Génération automatique d'un mot de passe sécurisé (32 caractères)
- ✅ Vérification obligatoire avant suppression du compte temporaire
- ✅ Rollback automatique en cas d'échec de vérification
- ✅ Sauvegarde dans Vault avec vérification
- ✅ Affichage du mot de passe à la fin (à sauvegarder)

### Récupération des credentials

Après l'exécution, vous pouvez récupérer les credentials depuis Vault :

```bash
kubectl exec -it vault-0 -n security -- vault kv get secret/keycloak/admin-permanent
```

Ou depuis un secret Kubernetes :

```bash
kubectl get secret keycloak-secrets -n keycloak -o jsonpath='{.data.admin-password}' | base64 -d
```

### Troubleshooting

#### Erreur: "Impossible de récupérer le mot de passe admin temporaire"

Vérifiez que le secret existe :

```bash
kubectl get secret keycloak-secrets -n keycloak
```

#### Erreur: "Impossible de se connecter avec l'admin temporaire"

Vérifiez que Keycloak est accessible :

```bash
curl http://keycloak.amazone.lan
kubectl get pods -n keycloak
```

#### Erreur: "La vérification des permissions a échoué"

Le script ne supprimera PAS l'admin temporaire pour préserver l'accès. Vous pouvez :
- Relancer le script
- Vérifier manuellement les rôles via l'interface web
- Supprimer manuellement l'admin temporaire après vérification

### Output exemple

```
============================================================
🔐 Keycloak - Initialisation de l'administrateur permanent
============================================================

ℹ️  Récupération du mot de passe admin temporaire depuis Kubernetes...
✅ Mot de passe admin récupéré (longueur: 32 caractères)
ℹ️  Connexion à Keycloak avec l'utilisateur 'admin'...
✅ Connexion réussie en tant que 'admin'

============================================================
Création de l'utilisateur administrateur permanent: killian
============================================================

ℹ️  Création de l'utilisateur...
✅ Utilisateur 'killian' créé (ID: 12345-abcd-6789)
ℹ️  Attribution des rôles realm-level...
✅ Rôles realm assignés: ['admin', 'create-realm', 'offline_access']
ℹ️  Attribution des rôles client 'realm-management'...
✅ Rôles client assignés: ['realm-admin', 'manage-realm', 'manage-users', ...]
✅ Utilisateur 'killian' configuré avec tous les rôles administrateurs

============================================================
Vérification des permissions de l'utilisateur 'killian'
============================================================

ℹ️  Connexion à Keycloak avec l'utilisateur 'killian'...
✅ Connexion réussie en tant que 'killian'
ℹ️  Test: Récupération des utilisateurs...
✅ OK - 2 utilisateurs récupérés
ℹ️  Test: Récupération des realms...
✅ OK - 1 realms récupérés
✅ ✨ L'utilisateur 'killian' a tous les accès administrateurs

============================================================
Suppression de l'utilisateur admin temporaire: admin
============================================================

⚠️  Suppression de l'utilisateur 'admin'...
✅ Utilisateur temporaire 'admin' supprimé avec succès

============================================================
Sauvegarde du mot de passe dans Vault
============================================================

✅ Mot de passe sauvegardé dans Vault
✅ Vérification réussie - credentials stockées dans Vault

============================================================
✅ Initialisation terminée avec succès!
============================================================

Credentials du nouvel administrateur:
  • URL:      http://keycloak.amazone.lan
  • Username: killian
  • Password: aBcD123456789XyZ...

⚠️  IMPORTANT: Sauvegardez ces credentials en lieu sûr!
```

## keycloak_01_secret.py

Script de synchronisation du client secret depuis Vault vers Keycloak.

### Description

Ce script lit le `client_secret` stocké dans Vault et le met à jour dans Keycloak pour le client `garage` du realm `garage`.

### Utilisation

```bash
cd scripts/keycloak_handler
python3 keycloak_01_secret.py
```

### Fonctionnalités

1. ✅ Connexion à Keycloak (realm `garage`)
2. ✅ Lecture du `client_secret` depuis Vault (`secret/keycloak/realms/garage/credentials`)
3. ✅ Recherche du client `garage` dans Keycloak
4. ✅ Mise à jour du secret dans Keycloak

### Cas d'usage

- Synchroniser le secret après une modification manuelle dans Vault
- Restaurer le secret après une réinitialisation
- Garantir la cohérence entre Vault et Keycloak

## keycloak_02_add_audience.py

Script pour ajouter l'audience mapper au client `garage`.

### Description

Ce script configure un mapper d'audience pour le client `garage` afin que tous les tokens JWT générés incluent `"aud": ["garage"]` dans leur payload.

### Utilisation

```bash
cd scripts/keycloak_handler
python3 keycloak_02_add_audience.py
```

### Fonctionnalités

1. ✅ Connexion à Keycloak (realm `garage`)
2. ✅ Recherche du client `garage`
3. ✅ Vérification si le mapper existe déjà
4. ✅ Ajout du mapper d'audience avec configuration :
   - `included.client.audience`: `garage`
   - `access.token.claim`: `true`
   - `id.token.claim`: `false`

### Résultat

Après exécution, tous les nouveaux tokens générés pour les utilisateurs du realm `garage` incluront :

```json
{
  "aud": ["garage"],
  "sub": "user-uuid",
  "name": "User Name",
  ...
}
```

### Note importante

⚠️ **Les tokens existants ne seront pas modifiés.** Les utilisateurs devront :
- Se reconnecter pour obtenir un nouveau token
- Ou attendre l'expiration de leur token actuel

Pour forcer la regénération de tous les tokens utilisateurs, relancez `keycloak_00_init.py` (étape de génération des tokens).

## keycloak_03_renew_tokens.py

Script pour renouveler tous les tokens des utilisateurs du realm `garage`.

### Description

Ce script lit automatiquement la liste des utilisateurs depuis Vault, récupère leurs mots de passe, génère de nouveaux tokens JWT et les stocke dans Vault.

### Utilisation

```bash
cd scripts/keycloak_handler
python3 keycloak_03_renew_tokens.py
```

### Fonctionnalités

1. ✅ Connexion à Vault avec le root token
2. ✅ Récupération des credentials du client `garage` depuis Vault
3. ✅ Liste automatique de tous les utilisateurs dans `/secret/keycloak/realms/garage/users/`
4. ✅ Pour chaque utilisateur :
   - Récupération du mot de passe depuis Vault
   - Génération d'un nouveau token JWT via Keycloak
   - Stockage du nouveau token dans Vault (en conservant le mot de passe)
5. ✅ Rapport détaillé avec nombre de succès/échecs

### Cas d'usage

- **Après ajout de l'audience mapper** : Regénérer tous les tokens pour qu'ils incluent `"aud": ["garage"]`
- **Après modification de la configuration Keycloak** : Appliquer les changements à tous les tokens
- **Rotation périodique des tokens** : Renouveler les tokens pour des raisons de sécurité
- **Après un incident** : Invalider et regénérer tous les tokens

### Output exemple

```bash
============================================================
🔐 Keycloak - Renouvellement des tokens utilisateurs
============================================================

ℹ️  Saisie du root token Vault...
✅ Token saisi (longueur: 28 caractères)

============================================================
Récupération des credentials du client
============================================================

ℹ️  Récupération des credentials du client depuis Vault...
✅ Client credentials récupérés (client_id: garage)

============================================================
Récupération de la liste des utilisateurs
============================================================

ℹ️  Récupération de la liste des utilisateurs depuis Vault...
✅ 13 utilisateurs trouvés dans Vault

============================================================
Renouvellement des tokens pour 13 utilisateur(s)
============================================================

ℹ️  Traitement de lilivet29@gmail.com...
✅ Token récupéré (longueur: 1234 caractères)
✅ Token stocké dans Vault pour lilivet29@gmail.com

ℹ️  Traitement de ineskopp35400@gmail.com...
✅ Token récupéré (longueur: 1234 caractères)
✅ Token stocké dans Vault pour ineskopp35400@gmail.com

[...]

============================================================
✅ Renouvellement des tokens terminé!
============================================================

Récapitulatif:
  • Realm:             garage
  • Client ID:         garage
  • Utilisateurs:      13
  • Tokens renouvelés: 13

Les tokens ont été renouvelés et stockés dans Vault.
Les nouveaux tokens incluent l'audience 'garage' si le mapper est configuré.
```

### Note importante

⚠️ Ce script nécessite que :
- Les utilisateurs existent dans Keycloak
- Les mots de passe soient stockés dans Vault
- Le client `garage` soit configuré dans Keycloak
- L'audience mapper soit configuré si vous voulez `"aud": ["garage"]` dans les tokens

