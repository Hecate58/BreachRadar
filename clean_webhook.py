import requests
import time

BOT_TOKEN = "8143357098:AAEZUsmztXNxwK8219JZX3-qaRXXqLfKiuY"

def reset_bot():
    # Étape 1: Supprimer le webhook
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook?drop_pending_updates=true"
    response = requests.get(url)
    print(f"Suppression du webhook: {response.status_code} - {response.json()}")
    
    # Attendre un moment
    time.sleep(1)
    
    # Étape 2: Vérifier l'état actuel
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getWebhookInfo"
    response = requests.get(url)
    print(f"État du webhook: {response.json()}")
    
    # Étape 3: Faire un getUpdates vide pour réinitialiser
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?offset=-1&limit=1"
    response = requests.get(url)
    print(f"Récupération des updates: {response.status_code}")

if __name__ == "__main__":
    reset_bot()
    print("Bot réinitialisé avec succès!")