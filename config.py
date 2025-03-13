#!/usr/bin/env python
# -*- coding: utf-8 -*-

# API Keys pour la surveillance du darkweb (services gratuits)
# Laissez ces valeurs à None si vous n'avez pas les clés, le code s'adaptera
REDDIT_CLIENT_ID = None  # Optionnel - obtenable gratuitement via https://www.reddit.com/prefs/apps
REDDIT_CLIENT_SECRET = None  # Optionnel 
REDDIT_USER_AGENT = "PythonSecurityBot/1.0"  # User-agent pour les requêtes Reddit
ALIENVAULT_API_KEY = None  # Optionnel - gratuit via https://otx.alienvault.com

# Configuration du bot Telegram
BOT_TOKEN = "8143357098:AAEZUsmztXNxwK8219JZX3-qaRXXqLfKiuY"  # Remplacez par votre token Telegram obtenu via BotFather
WEBHOOK_URL = "https://your-domain.com/webhook"  # URL de votre webhook en production

# API Keys pour les services tiers
VIRUSTOTAL_API_KEY = "0f694fa53021b262eb7e32bd3afc0b5757012cdb619156a2c461f425fbdc8c22"  # API key pour VirusTotal

# Configuration des services
# Nombre maximum de résultats à afficher dans les réponses
MAX_RESULTS_DISPLAY = 5

# Délais d'expiration pour les requêtes API (en secondes)
API_TIMEOUT = 10

# Paramètres de proxy (si nécessaire pour accéder à certains services)
# Laissez vide si vous n'utilisez pas de proxy
PROXY_URL = ""
PROXY_USERNAME = ""
PROXY_PASSWORD = ""

# Configuration de la base de données (pour stocker l'historique des analyses)
# Cette configuration utilise SQLite par défaut, mais peut être modifiée pour d'autres BDD
DB_TYPE = "sqlite"  # sqlite, mysql, postgresql
DB_PATH = "bot_data.db"  # Chemin pour SQLite, ignoré pour les autres types
DB_HOST = "localhost"  # Utilisé pour MySQL/PostgreSQL
DB_PORT = 3306  # Port par défaut pour MySQL
DB_NAME = "cybersecurity_bot"  # Nom de la base de données
DB_USER = "db_user"  # Utilisateur de la base de données
DB_PASSWORD = "db_password"  # Mot de passe de la base de données

# Paramètres de sécurité
# Taille minimale requise pour un mot de passe considéré comme "fort"
STRONG_PASSWORD_MIN_LENGTH = 12

# Seuils de risque
# Seuil au-dessus duquel un score de risque est considéré comme élevé (échelle 0-10)
HIGH_RISK_THRESHOLD = 7
# Seuil au-dessus duquel un score de risque est considéré comme moyen (échelle 0-10)
MEDIUM_RISK_THRESHOLD = 4

# Paramètres de génération de rapports
REPORT_TEMPLATE_PATH = "templates/report_template.html"
ENABLE_PDF_REPORTS = True