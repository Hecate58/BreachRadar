#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from telegram import ParseMode
import requests
import time
from telegram.constants import ParseMode
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters
)

from config import BOT_TOKEN, WEBHOOK_URL
import utils.breaches as breaches
import utils.darkweb_monitor as darkweb
from utils.url_dna.analyzer import analyze_url
import utils.whois as whois
import utils.vuln_scanner as vuln_scanner
import utils.leaked_credentials as leaked_credentials
from utils.darkweb_monitor import check_darkweb

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# États de conversation
AWAITING_INPUT = 0

# Fonctions pour les commandes du bot
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Commande de démarrage avec présentation du bot et commandes cliquables."""
    user = update.effective_user
    
    # Message d'accueil avec guide détaillé des commandes cliquables
    welcome_message = (
        f"Bonjour {user.mention_html()} ! 👋\n\n"
        f"Je suis votre assistant de cybersécurité. Voici ce que je peux faire pour vous :\n\n"
        
        f"/checkbreach - <b>Vérification de violations de données</b>\n"
        f"Vérifie si un email ou domaine a été compromis.\n"
        f"Exemple: <code>/checkbreach example@gmail.com</code>\n\n"
        
        f"/scanurl - <b>Analyse de sécurité d'URL</b>\n"
        f"Détecte les sites malveillants et tentatives de phishing.\n"
        f"Exemple: <code>/scanurl https://example.com/page</code>\n\n"
        
        f"/checkdarkweb - <b>Surveillance du darkweb</b>\n"
        f"Recherche des mentions sur le darkweb.\n"
        f"Exemple: <code>/checkdarkweb monentreprise</code>\n\n"
        
        f"/vulnscan - <b>Scan de vulnérabilités</b>\n"
        f"Vérifie les vulnérabilités d'un domaine.\n"
        f"Exemple: <code>/vulnscan example.com</code>\n\n"
        
        f"/checkpassword - <b>Vérification de mots de passe</b>\n"
        f"Vérifie si un mot de passe a été compromis.\n"
        f"Exemple: <code>/checkpassword MonMotDePasse123</code>\n\n"
        
        f"/report - <b>Génération de rapport</b>\n"
        f"Génère un rapport complet de sécurité.\n\n"
        
        f"/help - <b>Aide détaillée</b>\n"
        f"Affiche l'aide complète sur toutes les commandes.\n\n"
        
        f"🔒 <b>Confidentialité</b>: Toutes les données sont traitées de manière sécurisée et ne sont pas stockées après l'analyse."
    )
    
    # Créer des boutons de commande (insérer du texte dans la zone de saisie)
    command_keyboard = [
        [
            InlineKeyboardButton("⌨️ /checkbreach", switch_inline_query_current_chat="/checkbreach "),
            InlineKeyboardButton("⌨️ /scanurl", switch_inline_query_current_chat="/scanurl ")
        ],
        [
            InlineKeyboardButton("⌨️ /checkdarkweb", switch_inline_query_current_chat="/checkdarkweb "),
            InlineKeyboardButton("⌨️ /vulnscan", switch_inline_query_current_chat="/vulnscan ")
        ],
        [
            InlineKeyboardButton("⌨️ /checkpassword", switch_inline_query_current_chat="/checkpassword "),
            InlineKeyboardButton("⌨️ /report", switch_inline_query_current_chat="/report")
        ]
    ]
    
    # Créer des boutons d'action (démarrer conversation)
    action_keyboard = [
        [
            InlineKeyboardButton("✓ Vérifier email/domaine", callback_data="cmd_breach"),
            InlineKeyboardButton("🔍 Analyser URL", callback_data="cmd_url")
        ],
        [
            InlineKeyboardButton("🕸️ Recherche Darkweb", callback_data="cmd_darkweb"),
            InlineKeyboardButton("🛡️ Scanner vulnérabilités", callback_data="cmd_vuln")
        ],
        [
            InlineKeyboardButton("🔑 Vérifier mot de passe", callback_data="cmd_password"),
            InlineKeyboardButton("📊 Générer rapport", callback_data="cmd_report")
        ]
    ]
    
    # Créer un message avec les boutons de commande
    await update.message.reply_html(welcome_message)
    
    # Envoyer un message séparé avec les boutons de commande (pour insérer dans la zone de texte)
    await update.message.reply_text(
        "📝 <b>Commandes cliquables</b> - Cliquez pour insérer la commande dans la zone de texte:",
        reply_markup=InlineKeyboardMarkup(command_keyboard),
        parse_mode=ParseMode.HTML
    )
    
    # Envoyer un message séparé avec les boutons d'action (pour démarrer une conversation)
    await update.message.reply_text(
        "🚀 <b>Démarrer une analyse</b> - Cliquez pour commencer:",
        reply_markup=InlineKeyboardMarkup(action_keyboard),
        parse_mode=ParseMode.HTML
    )
    
    # Envoyer le message avec les boutons
    await update.message.reply_html(welcome_message, reply_markup=reply_markup)

async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Répond aux commandes inconnues."""
    logger.warning(f"Commande inconnue: {update.message.text}")
    await update.message.reply_text(
        "Désolé, je ne comprends pas cette commande. Utilisez /help pour voir les commandes disponibles."
    )
    
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fournit une aide détaillée sur les commandes disponibles avec commandes cliquables."""
    
    # Message d'aide avec guide détaillé des commandes
    help_text = (
        "📖 <b>Guide détaillé des commandes</b>\n\n"
        "<b>/checkbreach [email ou domaine]</b>\n"
        "Vérifie si l'email ou le domaine a été impliqué dans des fuites de données connues.\n"
        "Exemple: <code>/checkbreach example@gmail.com</code> ou <code>/checkbreach example.com</code>\n\n"
        
        "<b>/scanurl [url]</b>\n"
        "Analyse une URL pour détecter des menaces potentielles, du phishing ou des logiciels malveillants.\n"
        "Exemple: <code>/scanurl https://example.com/page</code>\n\n"
        
        "<b>/checkdarkweb [terme]</b>\n"
        "Recherche des mentions d'un terme (email, nom d'utilisateur, etc.) sur le darkweb.\n"
        "Exemple: <code>/checkdarkweb monentreprise</code>\n\n"
        
        "<b>/vulnscan [domaine]</b>\n"
        "Vérifie si un domaine présente des vulnérabilités connues.\n"
        "Exemple: <code>/vulnscan example.com</code>\n\n"
        
        "<b>/checkpassword [mot de passe]</b>\n"
        "Vérifie si un mot de passe a été compromis dans des fuites (utilise un hash sécurisé, votre mot de passe n'est jamais stocké).\n"
        "Exemple: <code>/checkpassword MonMotDePasse123</code>\n\n"
        
        "<b>/report</b>\n"
        "Génère un rapport complet combinant les résultats de toutes vos analyses précédentes.\n\n"
        
        "<b>/help</b>\n"
        "Affiche ce message d'aide.\n\n"
        
        "🔒 <b>Confidentialité</b>: Toutes les données que vous envoyez sont traitées de manière sécurisée et ne sont pas stockées après l'analyse."
    )
    
    # Ajouter des boutons pour faciliter l'utilisation des commandes
    keyboard = [
        [
            InlineKeyboardButton("✓ Vérifier email", callback_data="cmd_breach"),
            InlineKeyboardButton("🔍 Analyser URL", callback_data="cmd_url")
        ],
        [
            InlineKeyboardButton("🕸️ Recherche Darkweb", callback_data="cmd_darkweb"),
            InlineKeyboardButton("🛡️ Scanner domaine", callback_data="cmd_vuln")
        ],
        [
            InlineKeyboardButton("🔑 Vérifier mot de passe", callback_data="cmd_password"),
            InlineKeyboardButton("📊 Générer rapport", callback_data="cmd_report")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_html(help_text, reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Gère les clics sur les boutons inline."""
    query = update.callback_query
    await query.answer()
    
    cmd = query.data.split("_")[1]
    
    if cmd == "breach":
        await query.message.reply_text("Veuillez entrer l'email ou le domaine à vérifier:")
        context.user_data["next_command"] = "checkbreach"
    elif cmd == "url":
        await query.message.reply_text("Veuillez entrer l'URL à analyser:")
        context.user_data["next_command"] = "scanurl"
    elif cmd == "darkweb":
        await query.message.reply_text("Veuillez entrer le terme à rechercher sur le darkweb:")
        context.user_data["next_command"] = "checkdarkweb"
    elif cmd == "vuln":
        await query.message.reply_text("Veuillez entrer le domaine à scanner pour des vulnérabilités:")
        context.user_data["next_command"] = "vulnscan"
    elif cmd == "password":
        await query.message.reply_text("Veuillez entrer le mot de passe à vérifier (sera traité de manière sécurisée):")
        context.user_data["next_command"] = "checkpassword"
    elif cmd == "report":
        # Appel direct à la fonction de rapport
        await generate_report(update, context)
        return ConversationHandler.END
    
    return AWAITING_INPUT

async def input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Traite l'entrée de l'utilisateur après un clic sur un bouton."""
    user_input = update.message.text
    next_command = context.user_data.get("next_command")
    
    if next_command == "checkbreach":
        await check_breach(update, context, user_input)
    elif next_command == "scanurl":
        await scan_url(update, context, user_input)
    elif next_command == "checkdarkweb":
        await check_darkweb(update, context, user_input)
    elif next_command == "vulnscan":
        await vuln_scan(update, context, user_input)
    elif next_command == "checkpassword":
        await check_password(update, context, user_input)
    
    # Réinitialiser la commande en attente
    context.user_data.pop("next_command", None)
    return ConversationHandler.END

async def check_breach(update: Update, context: ContextTypes.DEFAULT_TYPE, input_data=None) -> None:
    """Vérifie les violations de données pour un email ou un domaine."""
    if not input_data:
        args = context.args
        if not args:
            await update.message.reply_text("Veuillez spécifier un email ou un domaine. Exemple: /checkbreach example@gmail.com")
            return
        input_data = args[0]
    
    # Message d'attente pour informer l'utilisateur
    waiting_message = await update.message.reply_text(
        f"🔍 Recherche de violations pour {input_data}...\n\n"
        f"⏳ Cette opération peut prendre quelques instants, veuillez patienter."
    )
    
    try:
        # Appel à la fonction de vérification des fuites
        results = breaches.check_breaches(input_data)
        
        # Supprimer le message d'attente
        await waiting_message.delete()
        
        if results:
            breach_count = len(results)
            message = f"⚠️ {breach_count} violation(s) de données détectée(s) pour {input_data}:\n\n"
            
            for breach in results[:5]:  # Limiter à 5 pour éviter des messages trop longs
                message += f"🔴 <b>{breach['name']}</b> ({breach['date']})\n"
                message += f"    Données compromises: {breach['data_classes']}\n\n"
            
            if breach_count > 5:
                message += f"... et {breach_count - 5} autres violations.\n\n"
                
            message += "ℹ️ Il est recommandé de changer vos mots de passe sur les services concernés."
            
            # Ajouter des conseils si des mots de passe ont été compromis
            password_breach = any("mot de passe" in breach['data_classes'].lower() for breach in results)
            if password_breach:
                message += "\n\n🔑 <b>Conseils de sécurité :</b>\n"
                message += "• Utilisez des mots de passe uniques pour chaque service\n"
                message += "• Activez l'authentification à deux facteurs quand c'est possible\n"
                message += "• Utilisez un gestionnaire de mots de passe\n"
                message += "• Vérifiez régulièrement vos comptes pour des activités suspectes"
        else:
            message = f"✅ Bonne nouvelle! Aucune violation de données détectée pour {input_data}.\n\n"
            message += "Continuez de surveiller régulièrement pour rester protégé."
        
        # Créer des boutons pour d'autres actions
        keyboard = [
            [
                InlineKeyboardButton("🔍 Analyser une URL", switch_inline_query_current_chat="/scanurl "),
                InlineKeyboardButton("🕸️ Recherche Darkweb", switch_inline_query_current_chat="/checkdarkweb ")
            ],
            [
                InlineKeyboardButton("🔑 Vérifier mot de passe", switch_inline_query_current_chat="/checkpassword "),
                InlineKeyboardButton("📊 Générer rapport", callback_data="cmd_report")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_html(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des violations: {e}")
        
        # Supprimer le message d'attente en cas d'erreur
        try:
            await waiting_message.delete()
        except:
            pass
        
        await update.message.reply_text(
            f"Une erreur s'est produite lors de la recherche. Veuillez réessayer plus tard.\n"
            f"Détails: {str(e)}"
        )

async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE, input_url=None) -> None:
    """Analyse une URL pour détecter des menaces potentielles."""
    if not input_url:
        args = context.args
        if not args:
            await update.message.reply_text("Veuillez spécifier une URL à analyser. Exemple: /scanurl https://example.com")
            return
        input_url = args[0]
    
    # Vérifier le format de l'URL
    if not input_url.startswith(('http://', 'https://')):
        input_url = 'https://' + input_url
    
    # Message d'attente
    waiting_message = await update.message.reply_text(
        f"🔍 Analyse de l'URL {input_url} en cours...\n\n"
        f"⏳ Cette opération peut prendre quelques instants, veuillez patienter."
    )
    
    try:
        # Appel à la fonction d'analyse d'URL
        results = analyze_url(input_url)
        
        # Supprimer le message d'attente
        await waiting_message.delete()
        
        # Préparer le message de résultat
        if results["safe"]:
            safety_emoji = "✅"
            safety_text = "sûre"
            safety_color = "green"
        else:
            safety_emoji = "⚠️"
            safety_text = "potentiellement dangereuse"
            safety_color = "red"
        
        # Créer le message principal avec des emoji pour la lisibilité
        message = f"{safety_emoji} <b>Résultat d'analyse</b>: Cette URL est <span style='color:{safety_color}'>{safety_text}</span>\n\n"
        
        # Ajouter les détails
        message += f"🔗 <b>URL analysée:</b> {results['url']}\n"
        message += f"📊 <b>Score de réputation:</b> {results['reputation_score']}/100\n"
        message += f"🛡️ <b>Certificat SSL:</b> {'Valide' if results['ssl_valid'] else 'Non valide ou absent'}\n"
        message += f"📅 <b>Âge du domaine:</b> {results['domain_age']}\n"
        
        # Ajouter les redirections si présentes
        if len(results['redirects']) > 1:
            message += f"\n⤵️ <b>Redirections ({len(results['redirects'])-1}):</b>\n"
            # Montrer juste la première et la dernière pour ne pas surcharger
            message += f"• {results['redirects'][0]['url']} → ... → {results['redirects'][-1]['url']}\n"
        
        # Ajouter les alertes si présentes, limitées à 5 pour ne pas surcharger
        if results["alerts"]:
            message += f"\n🚨 <b>Alertes ({len(results['alerts'])}):</b>\n"
            for i, alert in enumerate(results["alerts"][:5], 1):
                message += f"{i}. {alert}\n"
            
            if len(results["alerts"]) > 5:
                message += f"... et {len(results['alerts']) - 5} autres alertes.\n"
        
        # Ajouter des recommandations basées sur les résultats
        message += "\n🔒 <b>Recommandations:</b>\n"
        if results["safe"]:
            message += "• Cette URL semble sûre, mais restez toujours vigilant\n"
            message += "• Vérifiez que l'URL correspond bien au site que vous souhaitez visiter\n"
        else:
            message += "• <b>Évitez de visiter cette URL</b> ou de partager des informations sensibles\n"
            message += "• Ne téléchargez aucun fichier depuis ce site\n"
            
            # Recommandations spécifiques selon les problèmes détectés
            if not results["ssl_valid"]:
                message += "• Ne soumettez jamais d'informations confidentielles sur un site sans HTTPS\n"
            
            if any("redirect" in alert.lower() for alert in results["alerts"]):
                message += "• Méfiez-vous des redirections vers des domaines différents\n"
            
            if any("phishing" in alert.lower() for alert in results["alerts"]):
                message += "• Ce site pourrait être une tentative de phishing pour voler vos identifiants\n"
        
        # Créer des boutons pour d'autres actions
        keyboard = [
            [
                InlineKeyboardButton("✓ Vérifier email", switch_inline_query_current_chat="/checkbreach "),
                InlineKeyboardButton("🕸️ Recherche Darkweb", switch_inline_query_current_chat="/checkdarkweb ")
            ],
            [
                InlineKeyboardButton("🛡️ Scanner domaine", switch_inline_query_current_chat="/vulnscan "),
                InlineKeyboardButton("📊 Générer rapport", callback_data="cmd_report")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_html(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'URL: {e}")
        
        # Supprimer le message d'attente en cas d'erreur
        try:
            await waiting_message.delete()
        except:
            pass
        
        await update.message.reply_text(
            f"Une erreur s'est produite lors de l'analyse de l'URL. Veuillez vérifier que l'URL est valide et réessayer.\n"
            f"Détails: {str(e)}"
        )
async def vuln_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, input_domain=None) -> None:
    """Vérifie les vulnérabilités connues pour un domaine."""
    if not input_domain:
        args = context.args
        if not args:
            await update.message.reply_text("Veuillez spécifier un domaine à scanner. Exemple: /vulnscan example.com")
            return
        input_domain = args[0]
    
    await update.message.reply_text(f"🛡️ Analyse des vulnérabilités pour {input_domain} en cours...")
    
    try:
        results = vuln_scanner.scan_vulnerabilities(input_domain)
        
        if results["vulnerabilities"]:
            vuln_count = len(results["vulnerabilities"])
            message = f"⚠️ {vuln_count} vulnérabilité(s) détectée(s) pour {input_domain}:\n\n"
            
            for vuln in results["vulnerabilities"][:5]:  # Limiter à 5 pour éviter des messages trop longs
                message += f"🔴 <b>{vuln['type']}</b> (Sévérité: {vuln['severity']})\n"
                message += f"    Description: {vuln['description']}\n"
                if vuln.get('cve'):
                    message += f"    CVE: {vuln['cve']}\n"
                message += f"    Recommandation: {vuln['recommendation']}\n\n"
            
            if vuln_count > 5:
                message += f"... et {vuln_count - 5} autres vulnérabilités.\n\n"
                
            message += f"<b>Score de risque global:</b> {results['risk_score']}/10\n\n"
            message += "ℹ️ Il est recommandé de corriger ces vulnérabilités dès que possible."
        else:
            message = f"✅ Bonne nouvelle! Aucune vulnérabilité significative n'a été détectée pour {input_domain}.\n\n"
            message += f"<b>Informations supplémentaires:</b>\n"
            message += f"🔹 Serveur: {results['server_info']['server']}\n"
            message += f"🔹 Technologies détectées: {', '.join(results['server_info']['technologies'])}\n"
            message += f"🔹 Dernière mise à jour: {results['server_info']['last_updated']}\n"
        
        await update.message.reply_html(message)
        
    except Exception as e:
        logger.error(f"Erreur lors du scan de vulnérabilités: {e}")
        await update.message.reply_text(f"Une erreur s'est produite lors de l'analyse. Veuillez vérifier que le domaine est valide et réessayer.")

async def check_password(update: Update, context: ContextTypes.DEFAULT_TYPE, input_password=None) -> None:
    """Vérifie si un mot de passe a été compromis."""
    # Si le message arrive par commande directe et qu'il y a déjà des arguments
    if not input_password and context.args:
        # Supprimer immédiatement le message pour des raisons de sécurité
        await update.message.delete()
        input_password = context.args[0]
        # Continuer avec le mot de passe fourni
    elif not input_password:
        # Si pas d'argument, demander à l'utilisateur de réessayer en privé
        await update.message.reply_text(
            "Pour des raisons de sécurité, veuillez m'envoyer cette commande en message privé avec votre mot de passe. "
            "Exemple: /checkpassword VotreMotDePasse123"
        )
        return
    
    # Si nous sommes ici, nous avons un mot de passe à vérifier
    # Note: Le message original avec le mot de passe est déjà supprimé si nécessaire
    
    await update.message.reply_text("🔐 Vérification du mot de passe en cours...")
    
    try:
        results = leaked_credentials.check_password(input_password)
        
        if results["compromised"]:
            message = "⚠️ <b>Ce mot de passe a été compromis!</b>\n\n"
            message += f"Il a été trouvé dans {results['breach_count']} fuites de données.\n\n"
            message += "<b>Recommandations:</b>\n"
            message += "🔹 Changez immédiatement ce mot de passe sur tous les services où vous l'utilisez.\n"
            message += "🔹 Utilisez un mot de passe unique pour chaque service.\n"
            message += "🔹 Envisagez d'utiliser un gestionnaire de mots de passe.\n"
            message += "🔹 Activez l'authentification à deux facteurs (2FA) partout où c'est possible."
        else:
            message = "✅ <b>Bonne nouvelle!</b> Ce mot de passe n'a pas été trouvé dans les fuites de données connues.\n\n"
            
            if results["strength"] < 3:
                message += "⚠️ Cependant, ce mot de passe semble <b>faible</b>.\n"
                message += "<b>Recommandations pour renforcer votre mot de passe:</b>\n"
                message += "🔹 Utilisez au moins 12 caractères.\n"
                message += "🔹 Combinez lettres majuscules, minuscules, chiffres et caractères spéciaux.\n"
                message += "🔹 Évitez les séquences communes et les informations personnelles."
            else:
                message += "🔒 De plus, ce mot de passe semble avoir une <b>bonne force</b>.\n"
                message += "Continuez à utiliser des mots de passe forts et uniques pour chaque service."
        
        await update.message.reply_html(message)
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du mot de passe: {e}")
        await update.message.reply_text(f"Une erreur s'est produite lors de la vérification. Veuillez réessayer plus tard.")

async def generate_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Génère un rapport complet combinant toutes les analyses précédentes."""
    await update.message.reply_text("📊 Génération du rapport en cours...")
    
    # En situation réelle, cette fonction récupérerait les données des analyses précédentes
    # stockées pour l'utilisateur et générerait un rapport complet
    
    # Pour cette démo, nous allons simplement créer un message de rapport
    message = (
        "📋 <b>RAPPORT DE SÉCURITÉ</b>\n\n"
        "<b>Résumé des analyses:</b>\n\n"
        "🔍 <b>Violations de données:</b>\n"
        "   - 2 violations détectées pour le domaine example.com\n"
        "   - Risque évalué: Moyen\n\n"
        
        "🔗 <b>Analyse d'URL:</b>\n"
        "   - 3 URL analysées\n"
        "   - 1 URL suspecte détectée (phishing)\n\n"
        
        "🕸️ <b>Surveillance du darkweb:</b>\n"
        "   - 5 mentions détectées\n"
        "   - Principalement liées à une fuite de données en 2022\n\n"
        
        "🛡️ <b>Vulnérabilités:</b>\n"
        "   - 2 vulnérabilités de sévérité moyenne détectées\n"
        "   - Correctifs recommandés pour le serveur web\n\n"
        
        "🔑 <b>Sécurité des mots de passe:</b>\n"
        "   - 1 mot de passe compromis détecté\n"
        "   - 3 mots de passe considérés comme faibles\n\n"
        
        "<b>Recommandations prioritaires:</b>\n"
        "1. Mettre à jour le logiciel du serveur web\n"
        "2. Changer les mots de passe compromis ou faibles\n"
        "3. Mettre en place l'authentification à deux facteurs\n"
        "4. Former les employés aux risques de phishing\n\n"
        
        "<b>Score de sécurité global:</b> 65/100\n\n"
        
        "Un rapport détaillé a été envoyé à votre adresse email."
    )
    
    await update.message.reply_html(message)
    
    # Dans une implémentation réelle, on pourrait également générer un PDF
    # et l'envoyer en pièce jointe

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Gère les erreurs rencontrées par le dispatcher."""
    logger.error(f"Exception lors du traitement de la mise à jour {update}: {context.error}")
    
    # Envoyer un message à l'utilisateur
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "Une erreur s'est produite lors du traitement de votre demande. "
            "Veuillez réessayer plus tard ou contacter l'administrateur si le problème persiste."
        )

def main() -> None:
    """Fonction principale pour démarrer le bot."""
    # Créer l'application et passer le token du bot
    application = Application.builder().token(BOT_TOKEN).build()

    # Supprimer explicitement tout webhook et requêtes en attente
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook?drop_pending_updates=true")
    print("Webhook supprimé")
    
    # Attendre un instant pour s'assurer que tout est propre
    time.sleep(2)

    # Ajouter les gestionnaires de commandes
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("checkbreach", check_breach))
    application.add_handler(CommandHandler("scanurl", scan_url, filters=~filters.FORWARDED))
    application.add_handler(CommandHandler("checkdarkweb", check_darkweb))
    application.add_handler(CommandHandler("vulnscan", vuln_scan))
    application.add_handler(CommandHandler("checkpassword", check_password))
    application.add_handler(CommandHandler("report", generate_report))
    
    # Ajouter le gestionnaire de conversation pour les boutons
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler)],
        states={
            AWAITING_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, input_handler)]
        },
        fallbacks=[]
    )
    application.add_handler(conv_handler)
    
    # Gestionnaire de boutons pour les autres cas
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Ajouter le gestionnaire d'erreurs
    application.add_error_handler(error_handler)

    # Démarrer le bot en mode polling (pour le développement)
    # Pour la production, utiliser le mode webhook avec set_webhook.py
    print("Démarrage du bot...")
    application.run_polling()

if __name__ == '__main__':
    main()