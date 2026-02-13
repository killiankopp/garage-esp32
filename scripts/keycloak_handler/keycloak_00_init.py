#!/usr/bin/env python3
"""
Keycloak Garage Realm Initialization Script
Creates the 'garage' realm, configures it with 6-month token lifetime,
creates a client, and provisions users with their credentials and tokens.
"""

import json
import secrets
import subprocess
import sys
from typing import Optional, Dict, List, Tuple

from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakError


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_success(message: str):
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")


def print_error(message: str):
    print(f"{Colors.RED}❌ {message}{Colors.END}", file=sys.stderr)


def print_info(message: str):
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")


def print_warning(message: str):
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")


def print_header(message: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{message}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")


def connect_to_keycloak(username: str, password: str) -> Optional[KeycloakAdmin]:
    """
    Connect to Keycloak Admin API.

    Args:
        username: Username to authenticate
        password: Password to authenticate

    Returns:
        KeycloakAdmin instance or None if failed
    """
    print_info(f"Connexion à Keycloak avec l'utilisateur '{username}'...")

    try:
        # Désactiver les warnings SSL pour HTTP
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        keycloak_admin = KeycloakAdmin(
            server_url = "https://keycloak.amazone.lan/auth/",
            username=username,
            password=password,
            realm_name="master",
            user_realm_name="master",
            verify=False
        )

        # Test the connection
        keycloak_admin.get_users()
        print_success(f"Connexion réussie en tant que '{username}'")
        return keycloak_admin

    except KeycloakError as e:
        print_error(f"Erreur de connexion Keycloak: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue lors de la connexion: {str(e)}")
        return None


def generate_secure_password(length: int = 32) -> str:
    """
    Generate a secure random password.

    Args:
        length: Length of the password

    Returns:
        Secure random password
    """
    return secrets.token_urlsafe(length)[:length]


def create_realm(keycloak_admin: KeycloakAdmin, realm_name: str) -> bool:
    """
    Create a new realm in Keycloak.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        realm_name: Name of the realm to create

    Returns:
        True if successful, False otherwise
    """
    print_info(f"Création du realm '{realm_name}'...")

    try:
        # Check if realm exists
        realms = keycloak_admin.get_realms()
        if any(r['realm'] == realm_name for r in realms):
            print_warning(f"Le realm '{realm_name}' existe déjà")
            return True

        # Create realm
        realm_payload = {
            "realm": realm_name,
            "enabled": True,
            "displayName": "Garage",
            "displayNameHtml": "<b>Garage</b>"
        }

        keycloak_admin.create_realm(realm_payload)
        print_success(f"Realm '{realm_name}' créé avec succès")
        return True

    except KeycloakError as e:
        print_error(f"Erreur lors de la création du realm: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return False


def configure_realm_token_lifetime(keycloak_admin: KeycloakAdmin, realm_name: str) -> bool:
    """
    Configure realm to have 6-month token lifetime.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        realm_name: Name of the realm to configure

    Returns:
        True if successful, False otherwise
    """
    print_info(f"Configuration de la durée des tokens pour '{realm_name}' (6 mois)...")

    try:
        # 6 months in seconds = 6 * 30 * 24 * 60 * 60 = 15552000
        six_months_seconds = 15552000

        realm_update = {
            "accessTokenLifespan": six_months_seconds,
            "accessTokenLifespanForImplicitFlow": six_months_seconds,
            "ssoSessionIdleTimeout": six_months_seconds,
            "ssoSessionMaxLifespan": six_months_seconds,
            "offlineSessionIdleTimeout": six_months_seconds,
            "offlineSessionMaxLifespan": six_months_seconds,
            "accessCodeLifespan": six_months_seconds,
            "accessCodeLifespanUserAction": six_months_seconds,
            "accessCodeLifespanLogin": six_months_seconds,
        }

        keycloak_admin.update_realm(realm_name, realm_update)
        print_success(f"Configuration des tokens mise à jour (durée: 6 mois)")
        return True

    except KeycloakError as e:
        print_error(f"Erreur lors de la configuration du realm: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return False


def create_client(keycloak_admin: KeycloakAdmin, realm_name: str, client_id: str) -> Optional[Tuple[str, str]]:
    """
    Create a client in the specified realm.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        realm_name: Name of the realm
        client_id: Client ID to create

    Returns:
        Tuple of (client_id, client_secret) or None if failed
    """
    print_info(f"Création du client '{client_id}' dans le realm '{realm_name}'...")

    try:
        # Check if client exists
        clients = keycloak_admin.get_clients()
        existing_client = next((c for c in clients if c['clientId'] == client_id), None)

        if existing_client:
            print_warning(f"Le client '{client_id}' existe déjà")
            # Get the secret
            secret = keycloak_admin.get_client_secrets(existing_client['id'])
            return (client_id, secret['value'])

        # Create client
        client_payload = {
            "clientId": client_id,
            "enabled": True,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": True,
            "protocol": "openid-connect",
            "attributes": {
                "access.token.lifespan": "15552000"  # 6 months
            }
        }

        client_uuid = keycloak_admin.create_client(client_payload)
        print_success(f"Client '{client_id}' créé (ID: {client_uuid})")

        # Get client secret
        secret = keycloak_admin.get_client_secrets(client_uuid)
        print_success(f"Client secret récupéré")

        return (client_id, secret['value'])

    except KeycloakError as e:
        print_error(f"Erreur lors de la création du client: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def store_client_credentials_in_vault(client_id: str, client_secret: str, realm_name: str, vault_token: str) -> bool:
    """
    Store client credentials in Vault.

    Args:
        client_id: Client ID
        client_secret: Client secret
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        True if successful, False otherwise
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/credentials"
    print_info(f"Stockage des credentials du client dans Vault: {vault_path}")

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv put {vault_path} client_id={client_id} client_secret={client_secret}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        print_success(f"Credentials du client stockées dans Vault: {vault_path}")
        return True

    except subprocess.CalledProcessError as e:
        print_error(f"Erreur lors du stockage dans Vault: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return False


def get_garage_users() -> List[Dict[str, str]]:
    """
    Return the list of users to create in the garage realm.

    Returns:
        List of user dictionaries with firstName, lastName, and email
    """
    return [
        {"firstName": "Aurélie", "lastName": "VETTIER", "email": "lilivet29@gmail.com"},
        {"firstName": "Inès", "lastName": "KOPP", "email": "ineskopp35400@gmail.com"},
        {"firstName": "Aubin", "lastName": "KOPP", "email": "aubinkopp@gmail.com"},
        {"firstName": "Ewen", "lastName": "ROULLIER", "email": "ewen.roullier@gmail.com"},
        {"firstName": "Mathieu", "lastName": "ROULLIER", "email": "mathieu.roullier2012@gmail.com"},
        {"firstName": "Ethel", "lastName": "ROULLIER", "email": "roullierethel@gmail.com"},
        {"firstName": "Romane", "lastName": "VETTIER", "email": "romane.vettier@amazone.lan"},
        {"firstName": "Marc", "lastName": "VETTIER", "email": "marc.vettier@amazone.lan"},
        {"firstName": "Fabrice", "lastName": "LE BLAY", "email": "fabrice.leblay@amazone.lan"},
        {"firstName": "Karine", "lastName": "BAUDRY", "email": "karine.baudry@amazone.lan"},
        {"firstName": "Emarth", "lastName": "KOPP", "email": "emarth@hotmail.fr"},
        {"firstName": "Antelise", "lastName": "KOPP", "email": "antelise.kopp@free.fr"},
        {"firstName": "Nelly", "lastName": "KOPP", "email": "koppnelly1@gmail.com"},
    ]


def create_user_in_realm(keycloak_admin: KeycloakAdmin, user_data: Dict[str, str], password: str) -> Optional[str]:
    """
    Create a user in the current realm.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance (realm already set)
        user_data: Dictionary with firstName, lastName, email
        password: Password for the user

    Returns:
        User ID if successful, None otherwise
    """
    email = user_data['email']
    print_info(f"Création de l'utilisateur {email}...")

    try:
        # Check if user exists
        existing_users = keycloak_admin.get_users({"email": email})
        if existing_users:
            print_warning(f"L'utilisateur {email} existe déjà")
            return existing_users[0]['id']

        # Create user
        user_payload = {
            "username": email,
            "email": email,
            "firstName": user_data['firstName'],
            "lastName": user_data['lastName'],
            "enabled": True,
            "emailVerified": True,
            "credentials": [{
                "type": "password",
                "value": password,
                "temporary": False
            }]
        }

        user_id = keycloak_admin.create_user(user_payload)
        print_success(f"Utilisateur {email} créé (ID: {user_id})")
        return user_id

    except KeycloakError as e:
        print_error(f"Erreur lors de la création de l'utilisateur {email}: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def store_user_password_in_vault(email: str, password: str, realm_name: str, vault_token: str) -> bool:
    """
    Store user password in Vault.

    Args:
        email: User email
        password: User password
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        True if successful, False otherwise
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/users/{email}"
    print_info(f"  Stockage du mot de passe dans Vault...")

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv put {vault_path} password={password}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        print_success(f"  Mot de passe stocké dans Vault")
        return True

    except subprocess.CalledProcessError as e:
        print_error(f"  Erreur lors du stockage dans Vault: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return False


def get_user_token(email: str, password: str, realm_name: str, client_id: str, client_secret: str) -> Optional[str]:
    """
    Get an access token for a user.

    Args:
        email: User email (used as username)
        password: User password
        realm_name: Realm name
        client_id: Client ID
        client_secret: Client secret

    Returns:
        Access token if successful, None otherwise
    """
    print_info(f"  Récupération du token pour {email}...")

    try:
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Create KeycloakOpenID instance
        keycloak_openid = KeycloakOpenID(
            server_url="https://keycloak.amazone.lan/auth/",
            realm_name=realm_name,
            client_id=client_id,
            client_secret_key=client_secret,
            verify=False
        )

        # Get token
        token = keycloak_openid.token(email, password)
        access_token = token['access_token']

        print_success(f"  Token récupéré (longueur: {len(access_token)} caractères)")
        return access_token

    except KeycloakError as e:
        print_error(f"  Erreur lors de la récupération du token: {str(e)}")
        return None
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return None


def store_user_token_in_vault(email: str, token: str, realm_name: str, vault_token: str) -> bool:
    """
    Store user token in Vault.

    Args:
        email: User email
        token: Access token
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        True if successful, False otherwise
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/users/{email}"
    print_info(f"  Stockage du token dans Vault...")

    try:
        # First get existing data (password)
        get_result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv get -format=json {vault_path}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        existing_data = json.loads(get_result.stdout)
        password = existing_data.get('data', {}).get('data', {}).get('password', '')

        # Update with token
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv put {vault_path} password={password} token={token}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        print_success(f"  Token stocké dans Vault")
        return True

    except subprocess.CalledProcessError as e:
        print_error(f"  Erreur lors du stockage du token dans Vault: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return False


def get_vault_root_token() -> Optional[str]:
    """
    Ask user for the Vault root token.

    Returns:
        The root token or None if failed
    """
    print_info("Saisie du root token Vault...")
    print_info(
        "💡 Pour le récupérer: kubectl get secret vault-keys -n security -o jsonpath='{.data.root_token}' | base64 -d")
    print()

    try:
        import getpass
        token = getpass.getpass("Root token Vault: ")

        if not token or len(token.strip()) == 0:
            print_error("Le token ne peut pas être vide")
            return None

        print_success(f"Token saisi (longueur: {len(token)} caractères)")
        return token

    except KeyboardInterrupt:
        print_error("\nSaisie annulée par l'utilisateur")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def main():
    """Main execution function"""
    print_header("🔐 Keycloak - Initialisation du realm 'garage'")

    realm_name = "garage"
    client_id = "garage"

    # Step 1: Get admin credentials
    print_info("Connexion à Keycloak...")
    admin_username = input("Nom d'utilisateur admin Keycloak: ")
    import getpass
    admin_password = getpass.getpass("Mot de passe admin Keycloak: ")

    if not admin_username or not admin_password:
        print_error("Credentials admin requis")
        sys.exit(1)

    # Step 2: Connect to Keycloak (master realm)
    admin = connect_to_keycloak(admin_username, admin_password)
    if not admin:
        print_error("Impossible de se connecter à Keycloak")
        sys.exit(1)

    # Step 3: Get Vault token
    vault_token = get_vault_root_token()
    if not vault_token:
        print_error("Token Vault requis pour continuer")
        sys.exit(1)

    # Step 4: Create realm
    print_header(f"Création du realm '{realm_name}'")
    if not create_realm(admin, realm_name):
        print_error(f"Échec de la création du realm '{realm_name}'")
        sys.exit(1)

    # Step 5: Configure token lifetime (6 months)
    print_header(f"Configuration de la durée des tokens")
    if not configure_realm_token_lifetime(admin, realm_name):
        print_error("Échec de la configuration du realm")
        sys.exit(1)

    # Step 6: Switch to garage realm for client/user creation
    print_info(f"Connexion au realm '{realm_name}'...")
    garage_admin = connect_to_keycloak(admin_username, admin_password)
    if not garage_admin:
        print_error(f"Impossible de se connecter au realm '{realm_name}'")
        sys.exit(1)
    
    # Change realm
    garage_admin.realm_name = realm_name
    garage_admin.connection.realm_name = realm_name

    # Step 7: Create client
    print_header(f"Création du client '{client_id}'")
    client_credentials = create_client(garage_admin, realm_name, client_id)
    if not client_credentials:
        print_error(f"Échec de la création du client '{client_id}'")
        sys.exit(1)

    client_id_value, client_secret = client_credentials

    # Step 8: Store client credentials in Vault
    if not store_client_credentials_in_vault(client_id_value, client_secret, realm_name, vault_token):
        print_warning("Échec du stockage des credentials du client dans Vault")

    # Step 9: Create users
    print_header("Création des utilisateurs")
    users = get_garage_users()
    user_credentials = []  # Store for token generation

    for user_data in users:
        email = user_data['email']
        password = generate_secure_password(16)  # 16 char password for users

        print_info(f"\nTraitement de {email}...")

        # Create user
        user_id = create_user_in_realm(garage_admin, user_data, password)
        if not user_id:
            print_warning(f"Échec de la création de {email}")
            continue

        # Store password in Vault
        if not store_user_password_in_vault(email, password, realm_name, vault_token):
            print_warning(f"Échec du stockage du mot de passe pour {email}")

        # Save for token generation
        user_credentials.append((email, password))

    print_success(f"\n{len(user_credentials)} utilisateurs créés avec succès")

    # Step 10: Generate and store tokens for each user
    print_header("Génération et stockage des tokens utilisateurs")
    
    import time
    print_info("Attente de 3 secondes pour la propagation des utilisateurs...")
    time.sleep(3)

    for email, password in user_credentials:
        print_info(f"\nTraitement du token pour {email}...")

        # Get token
        token = get_user_token(email, password, realm_name, client_id_value, client_secret)
        if not token:
            print_warning(f"Échec de la récupération du token pour {email}")
            continue

        # Store token in Vault
        if not store_user_token_in_vault(email, token, realm_name, vault_token):
            print_warning(f"Échec du stockage du token pour {email}")

    # Final summary
    print_header("✅ Initialisation du realm 'garage' terminée!")
    print(f"\n{Colors.BOLD}Récapitulatif:{Colors.END}")
    print(f"  • Realm:          {Colors.GREEN}{realm_name}{Colors.END}")
    print(f"  • Client ID:      {Colors.GREEN}{client_id_value}{Colors.END}")
    print(f"  • Utilisateurs:   {Colors.GREEN}{len(user_credentials)}{Colors.END}")
    print(f"  • Token lifetime: {Colors.GREEN}6 mois{Colors.END}")
    print(f"\n{Colors.BOLD}Données stockées dans Vault:{Colors.END}")
    print(f"  • Client credentials: secret/keycloak/realms/{realm_name}/credentials")
    print(f"  • User credentials:   secret/keycloak/realms/{realm_name}/users/{{email}}/")
    print(f"\n{Colors.BOLD}Pour récupérer depuis Vault:{Colors.END}")
    print(f"  kubectl exec -it vault-0 -n security -- vault kv get secret/keycloak/realms/{realm_name}/credentials")
    print(f"  kubectl exec -it vault-0 -n security -- vault kv get secret/keycloak/realms/{realm_name}/users/{{email}}/\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\n\nInterruption par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print_error(f"\n\nErreur fatale: {str(e)}")
        sys.exit(1)

