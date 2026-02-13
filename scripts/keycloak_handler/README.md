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

