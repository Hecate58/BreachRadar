#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
from config import BOT_TOKEN

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def set_bot_commands():
    """Configure les commandes suggérées pour le bot."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyCommands"
    
    # Définir les commandes avec leurs descriptions
    commands = [
        {
            "command": "start",
            "description": "Démarrer le bot"
        },
        {
            "command": "checkbreach",
            "description": "Vérifier violations pour [email ou domaine]"
        },
        {
            "command": "scanurl",
            "description": "Analyser [URL] pour détecter des menaces"
        },
        {
            "command": "checkdarkweb",
            "description": "Rechercher [terme] sur le darkweb"
        },
        {
            "command": "vulnscan",
            "description": "Vérifier vulnérabilités pour [domaine]"
        },
        {
            "command": "checkpassword",
            "description": "Vérifier si [mot de passe] compromis"
        },
        {
            "command": "report",
            "description": "Générer un rapport complet"
        },
        {
            "command": "help",
            "description": "Afficher l'aide détaillée"
        }
    ]
    
    # Envoyer la requête à l'API Telegram
    data = {
        "commands": commands
    }
    
    try:
        response = requests.post(url, json=data)
        result = response.json()
        
        if result.get("ok"):
            logger.info("Commandes du bot configurées avec succès")
            return True
        else:
            logger.error(f"Erreur lors de la configuration des commandes: {result.get('description')}")
            return False
    except Exception as e:
        logger.error(f"Exception lors de la configuration des commandes: {e}")
        return False

if __name__ == "__main__":
    print("Configuration des commandes du bot...")
    success = set_bot_commands()
    
    if success:
        print("✅ Commandes configurées avec succès")
        print("\nLes commandes suivantes sont maintenant disponibles:")
        print("  /start - Démarrer le bot")
        print("  /checkbreach [email ou domaine] - Vérifier violations de données")
        print("  /scanurl [URL] - Analyser une URL pour détecter des menaces")
        print("  /checkdarkweb [terme] - Rechercher des mentions sur le darkweb")
        print("  /vulnscan [domaine] - Vérifier les vulnérabilités connues")
        print("  /checkpassword [mot de passe] - Vérifier si un mot de passe a été compromis")
        print("  /report - Générer un rapport complet")
        print("  /help - Afficher l'aide détaillée")
    else:
        print("❌ Échec de la configuration des commandes")