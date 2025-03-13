#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from config import BOT_TOKEN

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG  # Niveau DEBUG pour voir tous les messages
)
logger = logging.getLogger(__name__)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Commande simple pour tester le bot."""
    logger.info(f"Commande /start reçue de l'utilisateur {update.effective_user.id}")
    await update.message.reply_text('Bot de test est fonctionnel!')

async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Répète simplement le message de l'utilisateur."""
    logger.info(f"Message reçu de l'utilisateur {update.effective_user.id}: {update.message.text}")
    await update.message.reply_text(f"Vous avez dit: {update.message.text}")

def main() -> None:
    """Démarrer le bot en mode débogage."""
    logger.info("Démarrage du bot en mode débogage...")
    
    # Afficher des informations sur le token (masqué pour la sécurité)
    token = BOT_TOKEN
    visible_part = token[:4] + "..." + token[-4:] if len(token) > 8 else "Token invalide"
    logger.info(f"Utilisation du token: {visible_part}")
    
    # Créer l'application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Ajouter les gestionnaires
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("test", echo))
    
    logger.info("Handlers ajoutés, démarrage du polling...")
    # Démarrer le bot en mode polling avec des logs détaillés
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)

if __name__ == '__main__':
    main()