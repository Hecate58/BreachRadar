#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import sys
from config import BOT_TOKEN, WEBHOOK_URL

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def set_webhook():
    """Configure le webhook pour le bot Telegram."""
    telegram_api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook"
    
    # Paramètres pour configurer le webhook
    params = {
        'url': WEBHOOK_URL,
        'max_connections': 40,  # Nombre maximum de connexions simultanées
        'drop_pending_updates': True,  # Ignorer les mises à jour en attente lors du démarrage
        'allowed_updates': ['message', 'callback_query']  # Types de mises à jour autorisés
    }
    
    try:
        response = requests.post(telegram_api_url, params=params)
        response_data = response.json()
        
        if response.status_code == 200 and response_data.get('ok'):
            logger.info(f"Webhook configuré avec succès: {WEBHOOK_URL}")
            return True
        else:
            logger.error(f"Échec de la configuration du webhook: {response_data}")
            return False
    except Exception as e:
        logger.error(f"Erreur lors de la configuration du webhook: {e}")
        return False

def delete_webhook():
    """Supprime le webhook configuré pour le bot Telegram."""
    telegram_api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook"
    
    try:
        response = requests.get(telegram_api_url)
        response_data = response.json()
        
        if response.status_code == 200 and response_data.get('ok'):
            logger.info("Webhook supprimé avec succès")
            return True
        else:
            logger.error(f"Échec de la suppression du webhook: {response_data}")
            return False
    except Exception as e:
        logger.error(f"Erreur lors de la suppression du webhook: {e}")
        return False

def get_webhook_info():
    """Récupère les informations sur le webhook actuellement configuré."""
    telegram_api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/getWebhookInfo"
    
    try:
        response = requests.get(telegram_api_url)
        response_data = response.json()
        
        if response.status_code == 200 and response_data.get('ok'):
            webhook_info = response_data.get('result', {})
            logger.info(f"Informations du webhook: {webhook_info}")
            return webhook_info
        else:
            logger.error(f"Échec de la récupération des informations du webhook: {response_data}")
            return None
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des informations du webhook: {e}")
        return None

if __name__ == '__main__':
    # Vérifier les arguments de la ligne de commande
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'set':
            # Configurer le webhook
            if set_webhook():
                print("Webhook configuré avec succès")
            else:
                print("Échec de la configuration du webhook")
                
        elif command == 'delete':
            # Supprimer le webhook
            if delete_webhook():
                print("Webhook supprimé avec succès")
            else:
                print("Échec de la suppression du webhook")
                
        elif command == 'info':
            # Obtenir les informations sur le webhook
            webhook_info = get_webhook_info()
            if webhook_info:
                for key, value in webhook_info.items():
                    print(f"{key}: {value}")
            else:
                print("Impossible de récupérer les informations du webhook")
        else:
            print("Commande non reconnue. Utilisez 'set', 'delete' ou 'info'.")
    else:
        print("Utilisation: python set_webhook.py [set|delete|info]")