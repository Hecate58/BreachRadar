#!/usr/bin/env python
# -*- coding: utf-8 -*-

import telebot
from telebot import types
import re
import logging
from utils.darkweb_monitor import search_darkweb, get_risk_description, get_recommended_actions

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def handle_darkweb_command(bot: telebot.TeleBot):
    """
    Configure le gestionnaire de la commande /securitycheck.
    
    :param bot: Instance du bot Telegram
    """
    @bot.message_handler(commands=['checkdarkweb'])
    def darkweb_check(message: types.Message):
        """
        Gère la recherche de mentions sur le darkweb.
        
        :param message: Message Telegram
        """
        try:
            # Extraire le terme de recherche 
            search_term = message.text.split(' ', 1)[1].strip() if len(message.text.split()) > 1 else None
            
            # Valider le terme de recherche
            if not search_term:
                bot.reply_to(message, "❌ Veuillez fournir un terme de recherche (email, domaine, etc.).")
                return
            
            # Validation du format
            if not validate_search_term(search_term):
                bot.reply_to(message, "❌ Le terme de recherche est invalide. Utilisez un email, un domaine ou un identifiant valide.")
                return
            
            # Envoi d'un message d'attente
            wait_message = bot.reply_to(message, "🔍 Recherche en cours sur le darkweb et les sources publiques...")
            
            try:
                # Effectuer la recherche
                results = search_darkweb(search_term)
                
                # Préparer la réponse
                response = f"🕵️ Résultats de la recherche pour : {search_term}\n\n"
                
                # Niveau de risque et description
                risk_level = results.get('risk_level', 0)
                risk_description = get_risk_description(risk_level)
                response += f"🚨 Niveau de Risque : {risk_level}/10 ({risk_description})\n\n"
                
                # Ajouter les mentions si disponibles
                if results.get('mentions'):
                    response += "🔍 Mentions Trouvées :\n"
                    for i, mention in enumerate(results['mentions'][:5], 1):
                        source = mention.get('source', 'Source inconnue')
                        date = mention.get('date', 'Date inconnue')
                        category = mention.get('category', 'Catégorie non définie')
                        severity = mention.get('severity', 'Non spécifiée')
                        
                        response += f"{i}. Source : {source}\n"
                        response += f"   Date : {date}\n"
                        response += f"   Catégorie : {category}\n"
                        response += f"   Sévérité : {severity}\n\n"
                else:
                    response += "✅ Aucune mention suspecte trouvée.\n"
                
                # Recommandations
                recommended_actions = get_recommended_actions(risk_level, results.get('mentions', []))
                response += "\n📋 Recommandations :\n"
                for i, rec in enumerate(recommended_actions, 1):
                    response += f"{i}. {rec}\n"
                
                # Supprimer le message d'attente
                bot.delete_message(wait_message.chat.id, wait_message.message_id)
                
                # Limiter la longueur du message si nécessaire
                if len(response) > 4096:
                    response = response[:4096] + "\n\n[Message tronqué]"
                
                # Envoyer la réponse
                bot.reply_to(message, response)
                
                # Journalisation
                logger.info(f"Recherche darkweb réussie pour {search_term}. Niveau de risque : {risk_level}")
            
            except Exception as search_error:
                # Gérer les erreurs spécifiques à la recherche
                logger.error(f"Erreur lors de la recherche darkweb : {search_error}")
                bot.delete_message(wait_message.chat.id, wait_message.message_id)
                bot.reply_to(message, f"❌ Erreur lors de la recherche : {str(search_error)}")
        
        except IndexError:
            bot.reply_to(message, "❌ Erreur : Veuillez fournir un terme de recherche après /securitycheck")
        
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la commande checkdarkweb : {e}")
            bot.reply_to(message, f"❌ Une erreur inattendue est survenue : {str(e)}")

def validate_search_term(search_term: str) -> bool:
    """
    Valide le terme de recherche.
    
    :param search_term: Terme à rechercher
    :return: True si le terme est valide, False sinon
    """
    # Validation de base : email, nom de domaine, ou chaîne alphanumérique
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    return (
        re.match(email_pattern, search_term) is not None or
        re.match(domain_pattern, search_term) is not None or
        (len(search_term) >= 3 and len(search_term) <= 100)
    )

# Fonction optionnelle pour tester le module indépendamment
def main():
    """
    Point d'entrée pour tester le module.
    """
    from config import BOT_TOKEN
    
    # Initialiser le bot
    bot = telebot.TeleBot(BOT_TOKEN)
    
    # Configurer le gestionnaire de commande
    handle_darkweb_command(bot)
    
    print("Gestionnaire de commande /securitycheck prêt. Démarrez votre bot normalement.")

if __name__ == '__main__':
    main()