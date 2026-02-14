#!/usr/bin/env python3
"""
Keycloak Client Secret Synchronization Script
Reads the client_secret from Vault and updates it in Keycloak for the 'garage' client.
"""

import json
import subprocess
import sys
from typing import Optional

from keycloak import KeycloakAdmin
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


def connect_to_keycloak(username: str, password: str, realm_name: str = "master") -> Optional[KeycloakAdmin]:
    """
    Connect to Keycloak Admin API.

    Args:
        username: Username to authenticate
        password: Password to authenticate
        realm_name: Realm to connect to

    Returns:
        KeycloakAdmin instance or None if failed
    """
    print_info(f"Connexion à Keycloak avec l'utilisateur '{username}' (realm: {realm_name})...")

    try:
        # Désactiver les warnings SSL pour HTTP
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        keycloak_admin = KeycloakAdmin(
            server_url="https://keycloak.amazone.lan/",
            username=username,
            password=password,
            realm_name=realm_name,
            user_realm_name="master",
            verify=False
        )

        # Test the connection
        keycloak_admin.get_clients()
        print_success(f"Connexion réussie en tant que '{username}'")
        return keycloak_admin

    except KeycloakError as e:
        print_error(f"Erreur de connexion Keycloak: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue lors de la connexion: {str(e)}")
        return None


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


def read_client_secret_from_vault(realm_name: str, vault_token: str) -> Optional[str]:
    """
    Read client_secret from Vault.

    Args:
        realm_name: Realm name
        vault_token: Vault root token

    Returns:
        Client secret if successful, None otherwise
    """
    vault_path = f"secret/keycloak/realms/{realm_name}/credentials"
    print_info(f"Lecture du client_secret depuis Vault: {vault_path}")

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

        # Parse JSON output
        vault_data = json.loads(result.stdout)
        client_secret = vault_data.get('data', {}).get('data', {}).get('client_secret')

        if not client_secret:
            print_error("Le champ 'client_secret' n'existe pas dans Vault")
            return None

        print_success(f"Client secret récupéré depuis Vault (longueur: {len(client_secret)} caractères)")
        return client_secret

    except subprocess.CalledProcessError as e:
        print_error(f"Erreur lors de la lecture depuis Vault: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print_error(f"Erreur lors du parsing JSON: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def get_client_uuid(keycloak_admin: KeycloakAdmin, client_id: str) -> Optional[str]:
    """
    Get the internal UUID of a client by its clientId.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        client_id: Client ID (e.g., 'garage')

    Returns:
        Client UUID if found, None otherwise
    """
    print_info(f"Recherche du client '{client_id}'...")

    try:
        clients = keycloak_admin.get_clients()
        client = next((c for c in clients if c['clientId'] == client_id), None)

        if not client:
            print_error(f"Le client '{client_id}' n'existe pas dans le realm")
            return None

        client_uuid = client['id']
        print_success(f"Client '{client_id}' trouvé (UUID: {client_uuid})")
        return client_uuid

    except KeycloakError as e:
        print_error(f"Erreur lors de la recherche du client: {str(e)}")
        return None
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return None


def update_client_secret(keycloak_admin: KeycloakAdmin, client_uuid: str, secret: str) -> bool:
    """
    Update the client secret in Keycloak.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        client_uuid: Client UUID (internal ID)
        secret: New secret value

    Returns:
        True if successful, False otherwise
    """
    print_info(f"Mise à jour du client secret dans Keycloak...")

    try:
        # Get current client configuration
        client = keycloak_admin.get_client(client_uuid)

        # Update with new secret
        client['secret'] = secret

        # Update the client
        keycloak_admin.update_client(client_uuid, client)
        print_success(f"Client secret mis à jour avec succès")
        return True

    except KeycloakError as e:
        print_error(f"Erreur lors de la mise à jour du secret: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return False


def main():
    """Main execution function"""
    print_header("🔐 Keycloak - Synchronisation du client secret depuis Vault")

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

    # Step 2: Get Vault token
    vault_token = get_vault_root_token()
    if not vault_token:
        print_error("Token Vault requis pour continuer")
        sys.exit(1)

    # Step 3: Read client secret from Vault
    print_header(f"Lecture du secret depuis Vault")
    client_secret = read_client_secret_from_vault(realm_name, vault_token)
    if not client_secret:
        print_error("Impossible de récupérer le client_secret depuis Vault")
        sys.exit(1)

    # Step 4: Connect to Keycloak (garage realm)
    print_header(f"Connexion au realm '{realm_name}'")
    keycloak_admin = connect_to_keycloak(admin_username, admin_password, realm_name)
    if not keycloak_admin:
        print_error("Impossible de se connecter à Keycloak")
        sys.exit(1)

    # Step 5: Get client UUID
    print_header(f"Recherche du client '{client_id}'")
    client_uuid = get_client_uuid(keycloak_admin, client_id)
    if not client_uuid:
        print_error(f"Le client '{client_id}' n'existe pas")
        sys.exit(1)

    # Step 6: Update client secret
    print_header(f"Mise à jour du client secret")
    if not update_client_secret(keycloak_admin, client_uuid, client_secret):
        print_error("Échec de la mise à jour du client secret")
        sys.exit(1)

    # Final summary
    print_header("✅ Synchronisation terminée!")
    print(f"\n{Colors.BOLD}Récapitulatif:{Colors.END}")
    print(f"  • Realm:     {Colors.GREEN}{realm_name}{Colors.END}")
    print(f"  • Client ID: {Colors.GREEN}{client_id}{Colors.END}")
    print(f"  • Secret:    {Colors.GREEN}Synchronisé depuis Vault{Colors.END}")
    print(f"\n{Colors.BOLD}Le client secret du client '{client_id}' correspond maintenant à la valeur stockée dans Vault.{Colors.END}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\n\nInterruption par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print_error(f"\n\nErreur fatale: {str(e)}")
        sys.exit(1)

