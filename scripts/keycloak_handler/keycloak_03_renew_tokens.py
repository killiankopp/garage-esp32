#!/usr/bin/env python3
"""
Keycloak Token Renewal Script
Renews access tokens for all users in the garage realm and stores them in Vault.
"""

import json
import subprocess
import sys
from typing import Optional, List, Tuple

from keycloak import KeycloakOpenID
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


def get_client_credentials_from_vault(realm_name: str, vault_token: str) -> Optional[Tuple[str, str]]:
    """
    Get client credentials from Vault.

    Args:
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        Tuple of (client_id, client_secret) or None if failed
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/credentials"
    print_info(f"Récupération des credentials du client depuis Vault...")

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv get -format=json {vault_path}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        vault_data = json.loads(result.stdout)
        data = vault_data.get('data', {}).get('data', {})
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')

        if not client_id or not client_secret:
            print_error("Les credentials du client sont incomplets dans Vault")
            return None

        print_success(f"Client credentials récupérés (client_id: {client_id})")
        return (client_id, client_secret)

    except subprocess.CalledProcessError as e:
        print_error(f"Erreur lors de la lecture depuis Vault: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print_error(f"Erreur lors du parsing JSON: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def list_users_in_vault(realm_name: str, vault_token: str) -> List[str]:
    """
    List all users stored in Vault.

    Args:
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        List of user emails
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/users"
    print_info(f"Récupération de la liste des utilisateurs depuis Vault...")

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv list -format=json {vault_path}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        users = json.loads(result.stdout)
        # Remove trailing slashes from directory names
        users = [u.rstrip('/') for u in users if u]

        print_success(f"{len(users)} utilisateurs trouvés dans Vault")
        return users

    except subprocess.CalledProcessError as e:
        print_error(f"Erreur lors de la lecture depuis Vault: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print_error(f"Erreur lors du parsing JSON: {str(e)}")
        return []
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return []


def get_user_password_from_vault(email: str, realm_name: str, vault_token: str) -> Optional[str]:
    """
    Get user password from Vault.

    Args:
        email: User email
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        User password or None if failed
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/users/{email}"

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-it", "vault-0", "-n", "security", "--",
                "sh", "-c",
                f"VAULT_TOKEN='{vault_token}' vault kv get -format=json {vault_path}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        vault_data = json.loads(result.stdout)
        password = vault_data.get('data', {}).get('data', {}).get('password')

        if not password:
            print_error(f"  Mot de passe non trouvé pour {email}")
            return None

        return password

    except subprocess.CalledProcessError as e:
        print_error(f"  Erreur lors de la lecture du mot de passe: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print_error(f"  Erreur lors du parsing JSON: {str(e)}")
        return None
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return None


def get_user_token(email: str, password: str, realm_name: str, client_id: str, client_secret: str) -> Optional[str]:
    """
    Get a new access token for a user.

    Args:
        email: User email (used as username)
        password: User password
        realm_name: Realm name
        client_id: Client ID
        client_secret: Client secret

    Returns:
        Access token if successful, None otherwise
    """
    try:
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Create KeycloakOpenID instance
        keycloak_openid = KeycloakOpenID(
            server_url="https://keycloak.amazone.lan/",
            realm_name=realm_name,
            client_id=client_id,
            client_secret_key=client_secret,
            verify=False
        )

        # Get token
        token = keycloak_openid.token(email, password)
        access_token = token['access_token']

        return access_token

    except KeycloakError as e:
        print_error(f"  Erreur lors de la récupération du token: {str(e)}")
        return None
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return None


def store_user_token_in_vault(email: str, password: str, token: str, realm_name: str, vault_token: str) -> bool:
    """
    Store user token in Vault (keeping the password).

    Args:
        email: User email
        password: User password (to keep in Vault)
        token: New access token
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        True if successful, False otherwise
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/users/{email}"

    try:
        # Update with new token while keeping password
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

        return True

    except subprocess.CalledProcessError as e:
        print_error(f"  Erreur lors du stockage du token: {e.stderr}")
        return False
    except Exception as e:
        print_error(f"  Erreur inattendue: {str(e)}")
        return False


def main():
    """Main execution function"""
    print_header("🔐 Keycloak - Renouvellement des tokens utilisateurs")

    realm_name = "garage"

    # Step 1: Get Vault token
    vault_token = get_vault_root_token()
    if not vault_token:
        print_error("Token Vault requis pour continuer")
        sys.exit(1)

    # Step 2: Get client credentials from Vault
    print_header("Récupération des credentials du client")
    client_credentials = get_client_credentials_from_vault(realm_name, vault_token)
    if not client_credentials:
        print_error("Impossible de récupérer les credentials du client depuis Vault")
        sys.exit(1)

    client_id, client_secret = client_credentials

    # Step 3: List all users in Vault
    print_header("Récupération de la liste des utilisateurs")
    users = list_users_in_vault(realm_name, vault_token)
    if not users:
        print_warning("Aucun utilisateur trouvé dans Vault")
        sys.exit(0)

    # Step 4: Renew tokens for each user
    print_header(f"Renouvellement des tokens pour {len(users)} utilisateur(s)")

    success_count = 0
    failed_count = 0

    for email in users:
        print_info(f"\nTraitement de {email}...")

        # Get password from Vault
        password = get_user_password_from_vault(email, realm_name, vault_token)
        if not password:
            print_warning(f"  Mot de passe non trouvé pour {email}, passage au suivant")
            failed_count += 1
            continue

        # Get new token
        token = get_user_token(email, password, realm_name, client_id, client_secret)
        if not token:
            print_warning(f"  Échec de la récupération du token pour {email}")
            failed_count += 1
            continue

        print_success(f"  Token récupéré (longueur: {len(token)} caractères)")

        # Store new token in Vault
        if store_user_token_in_vault(email, password, token, realm_name, vault_token):
            print_success(f"  Token stocké dans Vault pour {email}")
            success_count += 1
        else:
            print_warning(f"  Échec du stockage du token pour {email}")
            failed_count += 1

    # Final summary
    print_header("✅ Renouvellement des tokens terminé!")
    print(f"\n{Colors.BOLD}Récapitulatif:{Colors.END}")
    print(f"  • Realm:            {Colors.GREEN}{realm_name}{Colors.END}")
    print(f"  • Client ID:        {Colors.GREEN}{client_id}{Colors.END}")
    print(f"  • Utilisateurs:     {Colors.GREEN}{len(users)}{Colors.END}")
    print(f"  • Tokens renouvelés: {Colors.GREEN}{success_count}{Colors.END}")
    if failed_count > 0:
        print(f"  • Échecs:           {Colors.RED}{failed_count}{Colors.END}")

    print(f"\n{Colors.BOLD}Les tokens ont été renouvelés et stockés dans Vault.{Colors.END}")
    print(f"Les nouveaux tokens incluent l'audience 'garage' si le mapper est configuré.\n")

    if failed_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\n\nInterruption par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print_error(f"\n\nErreur fatale: {str(e)}")
        sys.exit(1)

