#!/usr/bin/env python3
"""
Keycloak Audience Mapper Configuration Script
Adds audience mapper to the 'garage' client to include 'garage' in the 'aud' claim.
"""

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
            server_url="https://keycloak.amazone.lan/auth/",
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


def configure_client_audience_mapper(keycloak_admin: KeycloakAdmin, client_uuid: str, client_id: str) -> bool:
    """
    Configure audience mapper for the client to include the client_id in the 'aud' claim.

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        client_uuid: Client UUID (internal ID)
        client_id: Client ID (e.g., 'garage')

    Returns:
        True if successful, False otherwise
    """
    print_info(f"Configuration de l'audience mapper pour le client '{client_id}'...")

    try:
        # Check if mapper already exists
        mappers = keycloak_admin.get_mappers_from_client(client_uuid)
        existing_mapper = next((m for m in mappers if m.get('name') == 'audience-mapper'), None)

        if existing_mapper:
            print_warning(f"Le mapper 'audience-mapper' existe déjà")
            return True

        # Create audience mapper
        mapper_payload = {
            "name": "audience-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": client_id,
                "id.token.claim": "false",
                "access.token.claim": "true"
            }
        }

        keycloak_admin.add_mapper_to_client(client_uuid, mapper_payload)
        print_success(f"Audience mapper configuré (audience: {client_id})")
        return True

    except KeycloakError as e:
        print_error(f"Erreur lors de la configuration du mapper: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
        return False


def main():
    """Main execution function"""
    print_header("🔐 Keycloak - Configuration de l'audience mapper")

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

    # Step 2: Connect to Keycloak (garage realm)
    print_header(f"Connexion au realm '{realm_name}'")
    keycloak_admin = connect_to_keycloak(admin_username, admin_password, realm_name)
    if not keycloak_admin:
        print_error("Impossible de se connecter à Keycloak")
        sys.exit(1)

    # Step 3: Get client UUID
    print_header(f"Recherche du client '{client_id}'")
    client_uuid = get_client_uuid(keycloak_admin, client_id)
    if not client_uuid:
        print_error(f"Le client '{client_id}' n'existe pas")
        sys.exit(1)

    # Step 4: Configure audience mapper
    print_header(f"Configuration de l'audience mapper")
    if not configure_client_audience_mapper(keycloak_admin, client_uuid, client_id):
        print_error("Échec de la configuration de l'audience mapper")
        sys.exit(1)

    # Final summary
    print_header("✅ Configuration terminée!")
    print(f"\n{Colors.BOLD}Récapitulatif:{Colors.END}")
    print(f"  • Realm:     {Colors.GREEN}{realm_name}{Colors.END}")
    print(f"  • Client ID: {Colors.GREEN}{client_id}{Colors.END}")
    print(f"  • Audience:  {Colors.GREEN}{client_id}{Colors.END}")
    print(f"\n{Colors.BOLD}Les tokens générés incluront maintenant 'aud': ['{client_id}'] dans leur payload.{Colors.END}")
    print(f"\n{Colors.BOLD}Note:{Colors.END} Les tokens existants ne seront pas modifiés. Les utilisateurs devront générer de nouveaux tokens.")
    print(f"Pour regénérer les tokens, utilisez le script keycloak_00_init.py ou demandez aux utilisateurs de se reconnecter.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\n\nInterruption par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print_error(f"\n\nErreur fatale: {str(e)}")
        sys.exit(1)

