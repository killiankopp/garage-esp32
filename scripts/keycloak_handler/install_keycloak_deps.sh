#!/bin/bash
# Installation des dépendances pour le script d'initialisation Keycloak

set -e

echo "============================================"
echo "🔧 Installation des dépendances Python"
echo "============================================"
echo ""

# Vérifier que Python 3 est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    echo "   Installez-le avec: brew install python3"
    exit 1
fi

echo "✅ Python 3 trouvé: $(python3 --version)"
echo ""

# Vérifier que kubectl est installé
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl n'est pas installé"
    echo "   Installez-le avec: brew install kubectl"
    exit 1
fi

echo "✅ kubectl trouvé: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
echo ""

# Créer un environnement virtuel si demandé
if [ "$1" == "--venv" ]; then
    echo "📦 Création d'un environnement virtuel Python..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✅ Environnement virtuel activé"
    echo ""
fi

# Installer les dépendances
echo "📥 Installation de python-keycloak..."
pip install -r requirements.txt

echo ""
echo "============================================"
echo "✅ Installation terminée!"
echo "============================================"
echo ""
echo "Pour exécuter le script:"
echo "  python3 keycloak_00_init.py"
echo ""
echo "Ou directement:"
echo "  ./keycloak_00_init.py"
echo ""

if [ "$1" == "--venv" ]; then
    echo "Note: N'oubliez pas d'activer l'environnement virtuel:"
    echo "  source venv/bin/activate"
    echo ""
fi

