#!/bin/bash

# Script d'installation pour BreacheRadar_bot

# Vérifier que Python 3.8+ est installé
python_version=$(python3 --version | cut -d' ' -f2)
required_version="3.8.0"

# Fonction de comparaison de versions
version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

if ! version_gt "$python_version" "$required_version"; then
    echo "Erreur : Python 3.8 ou supérieur est requis. Version actuelle : $python_version"
    exit 1
fi

# Créer un environnement virtuel
echo "Création de l'environnement virtuel..."
python3 -m venv venv

# Activer l'environnement virtuel
source venv/bin/activate

# Mettre à jour pip
pip install --upgrade pip

# Installer les dépendances
echo "Installation des dépendances..."
pip install -r requirements.txt

# Installer wkhtmltopdf (requis pour pdfkit)
echo "Installation de wkhtmltopdf (requis pour la génération de PDF)..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y wkhtmltopdf
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install wkhtmltopdf
else
    echo "Veuillez installer manuellement wkhtmltopdf pour votre système."
fi

# Créer les répertoires nécessaires
mkdir -p reports_cache logs

# Configuration initiale
echo "Configuration initiale..."
python3 set_commands.py
python3 set_webhook.py

# Message de fin
echo "Installation terminée !"
echo "N'oubliez pas de configurer votre token Telegram dans config.py"