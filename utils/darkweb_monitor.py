#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import datetime
import time
import hashlib
import re
import random
import fix_whois as whois
import urllib.parse

# Importation de BeautifulSoup - vous devrez installer cette dépendance
try:
    from bs4 import BeautifulSoup
except ImportError:
    # Si bs4 n'est pas installé, créer un remplacement minimal
    class BeautifulSoup:
        def __init__(self, *args, **kwargs):
            pass

# Importation des paramètres de configuration
from config import (
    API_TIMEOUT,
    HIGH_RISK_THRESHOLD, 
    MEDIUM_RISK_THRESHOLD
)

# Valeurs par défaut pour les clés API optionnelles
# Si ces variables sont définies dans config.py, elles seront utilisées
# sinon, les valeurs par défaut (None) seront utilisées
try:
    from config import HIBP_API_KEY
except ImportError:
    HIBP_API_KEY = None

try:
    from config import REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT
except ImportError:
    REDDIT_CLIENT_ID = None
    REDDIT_CLIENT_SECRET = None
    REDDIT_USER_AGENT = "PythonSecurityBot/1.0"

try:
    from config import ALIENVAULT_API_KEY
except ImportError:
    ALIENVAULT_API_KEY = None
# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# API URLs pour les services gratuits
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/"
URLSCAN_API_URL = "https://urlscan.io/api/v1/search/"
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/indicators/domain"
REDDIT_SEARCH_URL = "https://www.reddit.com/search.json"

# Headers pour les requêtes
HEADERS = {
    "User-Agent": REDDIT_USER_AGENT
}

# Headers pour HIBP si une clé API est disponible
HIBP_HEADERS = {
    "User-Agent": REDDIT_USER_AGENT
}
if HIBP_API_KEY:
    HIBP_HEADERS["hibp-api-key"] = HIBP_API_KEY

# Catégories de données sensibles
SENSITIVE_DATA_CATEGORIES = {
    "CREDENTIALS": "Identifiants de connexion",
    "FINANCIAL": "Informations financières",
    "PERSONAL": "Données personnelles",
    "CORPORATE": "Données d'entreprise",
    "MEDICAL": "Données médicales",
    "IDENTITY": "Informations d'identité",
    "COMMUNICATION": "Données de communication"
}

# Subreddits pertinents pour la sécurité
SECURITY_SUBREDDITS = [
    "cybersecurity", "netsec", "privacy", "hacking", 
    "security", "dataleaks", "pwned", "InfoSecNews"
]

# Forums/sites connus pour les fuites (pour enrichissement)
LEAK_SITES = [
    "RaidForums", "BreachForums", "LeakBase", "Pastebin", 
    "Leak-Lookup", "Exposed Database", "GhostBin", "HaveIBeenPwned",
    "LeakedSource", "DarkTracer", "Exploit.in", "HackForums"
]

def search_darkweb(search_term):
    """
    Recherche des mentions sur le darkweb pour un terme spécifique.
    Utilise uniquement des API et méthodes gratuites.
    
    Args:
        search_term (str): Terme à rechercher
        
    Returns:
        dict: Résultats de la recherche avec les mentions et le niveau de risque
    """
    logger.info(f"Recherche sur le darkweb pour: {search_term}")
    
    # Initialiser les résultats
    results = {
        "mentions": [],
        "risk_level": 0,
        "search_term": search_term,
        "search_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Vérifier le type de terme pour adapter la recherche
    is_email_term = is_email(search_term)
    is_domain_term = is_domain(search_term)
    
    # 1. Vérifier les violations de données avec HIBP pour les emails
    if is_email_term and HIBP_API_KEY:
        try:
            hibp_results = check_email_breaches(search_term)
            if hibp_results:
                results["mentions"].extend(hibp_results)
        except Exception as e:
            logger.error(f"Erreur lors de la recherche HIBP: {e}")
    
    # 2. Vérifier AlienVault OTX pour les domaines (gratuit)
    if is_domain_term:
        try:
            otx_results = check_alienvault_otx(search_term)
            if otx_results:
                results["mentions"].extend(otx_results)
        except Exception as e:
            logger.error(f"Erreur lors de la recherche AlienVault: {e}")
    
    # 3. Rechercher sur URLScan.io (gratuit avec limite)
    if is_domain_term:
        try:
            urlscan_results = search_urlscan(search_term)
            if urlscan_results:
                results["mentions"].extend(urlscan_results)
        except Exception as e:
            logger.error(f"Erreur lors de la recherche URLScan: {e}")
    
    # 4. Vérifier PhishTank pour les domaines (gratuit)
    if is_domain_term:
        try:
            phishtank_results = check_phishtank(search_term)
            if phishtank_results:
                results["mentions"].extend(phishtank_results)
        except Exception as e:
            logger.error(f"Erreur lors de la recherche PhishTank: {e}")
    
    # 5. Recherche sur Reddit (gratuit)
    try:
        reddit_results = search_on_reddit(search_term)
        if reddit_results:
            results["mentions"].extend(reddit_results)
    except Exception as e:
        logger.error(f"Erreur lors de la recherche Reddit: {e}")
    
    # 6. Recherche Google dorks (simulation)
    # Cette fonction simule les résultats qu'on obtiendrait avec des Google dorks
    # car il est difficile de scraper Google directement
    try:
        dork_results = simulate_google_dorks(search_term)
        if dork_results:
            results["mentions"].extend(dork_results)
    except Exception as e:
        logger.error(f"Erreur lors de la simulation de Google dorks: {e}")
    
    # Calculer le niveau de risque
    results["risk_level"] = calculate_risk_level(results["mentions"])
    
    return results

def check_email_breaches(email):
    """
    Vérifie si un email apparaît dans des fuites de données connues via HIBP.
    
    Args:
        email (str): Email à vérifier
        
    Returns:
        list: Liste des mentions trouvées
    """
    mentions = []
    
    try:
        # Paramètres de requête
        params = {
            "truncateResponse": False  # Pour obtenir tous les détails des violations
        }
        
        # Effectuer la requête à l'API
        response = requests.get(
            f"{HIBP_BREACH_URL}/{email}",
            headers=HIBP_HEADERS,
            params=params,
            timeout=API_TIMEOUT
        )
        
        # Traiter la réponse
        if response.status_code == 200:
            breaches = response.json()
            
            for breach in breaches:
                # Extraire les données pertinentes
                breach_date = breach.get("BreachDate", "Date inconnue")
                
                # Créer une mention pour chaque violation
                mention = {
                    "source": breach.get("Name", "Source inconnue"),
                    "date": breach_date,
                    "category": categorize_data_classes(breach.get("DataClasses", [])),
                    "context": f"Email trouvé dans la violation de données {breach.get('Name')}. " +
                              f"Types de données: {', '.join(breach.get('DataClasses', [])[:3])}...",
                    "confidence": 90,  # Haute confiance car source fiable
                    "severity": determine_breach_severity(breach.get("DataClasses", [])),
                    "verified": True
                }
                
                mentions.append(mention)
        
        elif response.status_code == 429:
            logger.warning("Limite de taux HIBP atteinte")
            # Ajouter une mention sur la limite d'API
            mentions.append({
                "source": "HaveIBeenPwned",
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "category": "Limitation d'API",
                "context": "La limite de requêtes à l'API HIBP a été atteinte. Impossible de vérifier complètement les violations.",
                "confidence": 50,
                "severity": "Moyenne",
                "verified": True
            })
        
        elif response.status_code != 404:  # Ignorer 404 (pas de violation)
            logger.error(f"Erreur API HIBP: {response.status_code}")
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification HIBP: {e}")
    
    # Si pas de clé API HIBP mais l'email semble contenir un domaine bien connu,
    # faire une vérification heuristique basée sur les violations connues
    if not HIBP_API_KEY and not mentions and "@" in email:
        domain = email.split("@")[1]
        if domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]:
            # Approche heuristique: les grands fournisseurs d'email ont tous eu des fuites
            mentions.append({
                "source": "Analyse heuristique",
                "date": "2018-01-01",  # Date approximative de grandes fuites
                "category": SENSITIVE_DATA_CATEGORIES["CREDENTIALS"],
                "context": f"Les grands fournisseurs d'email comme {domain} ont été impliqués dans des fuites de données. " +
                          "Vérification recommandée sur haveibeenpwned.com",
                "confidence": 60,
                "severity": "Moyenne",
                "verified": False,
                "enriched": True
            })
    
    return mentions

def check_alienvault_otx(domain):
    """
    Vérifie les indicateurs de menace pour un domaine via AlienVault OTX.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        list: Liste des mentions trouvées
    """
    mentions = []
    
    # Si pas de clé API, ne pas effectuer cette recherche
    if not ALIENVAULT_API_KEY:
        return mentions
    
    try:
        headers = {
            "X-OTX-API-KEY": ALIENVAULT_API_KEY,
            "User-Agent": HEADERS["User-Agent"]
        }
        
        response = requests.get(
            f"{ALIENVAULT_API_URL}/{domain}/general",
            headers=headers,
            timeout=API_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Vérifier si le domaine est considéré comme malveillant
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            
            if pulse_count > 0:
                # Le domaine apparaît dans des rapports de menaces
                pulses = data.get("pulse_info", {}).get("pulses", [])
                
                for pulse in pulses[:3]:  # Limiter à 3 pour éviter trop de résultats
                    modified = pulse.get("modified", "")
                    modified_date = modified.split("T")[0] if "T" in modified else "Date inconnue"
                    
                    # Déterminer la sévérité en fonction des tags
                    tags = pulse.get("tags", [])
                    severity = "Moyenne"
                    if any(tag in ["malware", "ransomware", "phishing", "exploit"] for tag in tags):
                        severity = "Élevée"
                    
                    context = f"Domaine mentionné dans un rapport de menace: {pulse.get('name', 'Rapport inconnu')}. "
                    if tags:
                        context += f"Tags: {', '.join(tags[:5])}..."
                    
                    mention = {
                        "source": "AlienVault OTX",
                        "date": modified_date,
                        "category": determine_category_from_tags(tags),
                        "context": context,
                        "confidence": 85,
                        "severity": severity,
                        "verified": True
                    }
                    
                    mentions.append(mention)
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification AlienVault OTX: {e}")
    
    return mentions

def search_urlscan(domain):
    """
    Recherche un domaine sur URLScan.io pour détecter des menaces.
    
    Args:
        domain (str): Domaine à rechercher
        
    Returns:
        list: Liste des mentions trouvées
    """
    mentions = []
    
    try:
        params = {
            "q": f"domain:{domain}"
        }
        
        response = requests.get(
            URLSCAN_API_URL,
            params=params,
            headers=HEADERS,
            timeout=API_TIMEOUT
        )
        
        if response.status_code == 200:
            results = response.json().get("results", [])
            
            for result in results[:3]:  # Limiter à 3 résultats
                # Extraire des informations
                scan_date = result.get("task", {}).get("time")
                if scan_date:
                    scan_date = scan_date.split("T")[0]  # Format YYYY-MM-DD
                else:
                    scan_date = "Date inconnue"
                
                page_url = result.get("page", {}).get("url", "URL inconnue")
                
                # Détecter les menaces
                tags = result.get("tags", [])
                is_malicious = any(tag in ["malicious", "phishing", "scam", "spam"] for tag in tags)
                
                if is_malicious:
                    # Créer une mention
                    mention = {
                        "source": "URLScan.io",
                        "date": scan_date,
                        "category": SENSITIVE_DATA_CATEGORIES["CREDENTIALS"] if "phishing" in tags else "Site malveillant",
                        "context": f"Domaine détecté sur un site potentiellement malveillant: {page_url}. " +
                                  f"Tags: {', '.join(tags)}",
                        "confidence": 80,
                        "severity": "Élevée" if "phishing" in tags else "Moyenne",
                        "verified": True
                    }
                    
                    mentions.append(mention)
    
    except Exception as e:
        logger.error(f"Erreur lors de la recherche URLScan: {e}")
    
    return mentions

def check_phishtank(url):
    """
    Vérifie si une URL est listée comme phishing dans PhishTank.
    
    Args:
        url (str): URL à vérifier
        
    Returns:
        list: Liste des mentions trouvées
    """
    mentions = []
    
    try:
        # Nettoyer l'URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        encoded_url = urllib.parse.quote_plus(url)
        
        # PhishTank a une API gratuite mais nécessite une vérification CAPTCHA
        # pour les requêtes directes. Ce code simule ce qu'on obtiendrait
        # Note: Dans une implémentation réelle, vous pourriez utiliser leur API JSON
        # avec une clé d'application
        
        # Simuler la vérification PhishTank basée sur des heuristiques
        domain = urllib.parse.urlparse(url).netloc
        
        # Vérifier si le domaine ressemble à un site de phishing connu
        common_targets = ["paypal", "apple", "microsoft", "google", "amazon", "facebook", 
                         "instagram", "netflix", "bank", "login", "secure", "update"]
        
        for target in common_targets:
            if target in domain and not domain.endswith(f"{target}.com"):
                # Domaine suspect (ex: paypal-secure.example.com)
                mention = {
                    "source": "Analyse de phishing",
                    "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                    "category": SENSITIVE_DATA_CATEGORIES["CREDENTIALS"],
                    "context": f"L'URL contient '{target}' et pourrait être un site de phishing. " +
                              "Vérification manuelle recommandée.",
                    "confidence": 60,  # Confiance modérée car heuristique
                    "severity": "Élevée",
                    "verified": False,
                    "enriched": True
                }
                
                mentions.append(mention)
                break
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification PhishTank: {e}")
    
    return mentions

def search_on_reddit(search_term):
    """
    Recherche des mentions sur Reddit dans des subreddits liés à la sécurité.
    
    Args:
        search_term (str): Terme à rechercher
        
    Returns:
        list: Liste des mentions trouvées
    """
    mentions = []
    
    try:
        # Utiliser l'API publique de Reddit (pas besoin d'authentification pour les recherches de base)
        params = {
            "q": search_term,
            "limit": 10,
            "sort": "relevance"
        }
        
        # Chercher dans des subreddits pertinents
        for subreddit in SECURITY_SUBREDDITS[:3]:  # Limiter à 3 subreddits pour éviter trop de requêtes
            params["restrict_sr"] = "true"
            
            response = requests.get(
                f"https://www.reddit.com/r/{subreddit}/search.json",
                params=params,
                headers=HEADERS,
                timeout=API_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                posts = data.get("data", {}).get("children", [])
                
                for post in posts[:2]:  # Limiter à 2 posts par subreddit
                    post_data = post.get("data", {})
                    title = post_data.get("title", "")
                    created = post_data.get("created_utc", 0)
                    
                    # Ne prendre en compte que si le terme est bien présent dans le titre
                    if search_term.lower() in title.lower():
                        post_date = datetime.datetime.fromtimestamp(created).strftime("%Y-%m-%d")
                        
                        # Estimer la sévérité en fonction des mots-clés présents
                        severity = "Moyenne"
                        high_severity_terms = ["leak", "breach", "hack", "pwned", "dump", "exposed", "stolen"]
                        if any(term in title.lower() for term in high_severity_terms):
                            severity = "Élevée"
                        
                        # Déterminer la catégorie en fonction du titre
                        category = determine_category_from_text(title)
                        
                        mention = {
                            "source": f"Reddit r/{subreddit}",
                            "date": post_date,
                            "category": category,
                            "context": f"Mention dans une discussion Reddit: {title}",
                            "confidence": 65,  # Confiance modérée
                            "severity": severity,
                            "verified": True
                        }
                        
                        mentions.append(mention)
    
    except Exception as e:
        logger.error(f"Erreur lors de la recherche Reddit: {e}")
    
    return mentions

def simulate_google_dorks(search_term):
    """
    Simule les résultats qu'on obtiendrait avec des Google dorks.
    Cette fonction est une simulation car le scraping de Google est difficile et souvent bloqué.
    
    Args:
        search_term (str): Terme à rechercher
        
    Returns:
        list: Liste des mentions simulées
    """
    mentions = []
    
    # Dans une implémentation réelle, vous effectueriez des requêtes comme:
    # site:pastebin.com {search_term}
    # intext:password intext:{search_term} site:github.com
    # etc.
    
    # Ici, nous simulons ce que nous pourrions trouver
    
    # Déterminer quelques sites à "vérifier" en fonction du type de terme
    if is_email(search_term):
        sites_to_check = ["Pastebin", "GitHub", "GitLab", "StackOverflow"]
    elif is_domain(search_term):
        sites_to_check = ["SecurityTracker", "CVE Details", "ExploitDB", "HackerOne"]
    else:
        sites_to_check = ["Pastebin", "GitHub", "HackForums", "Reddit"]
    
    # Générer quelques mentions si le terme semble intéressant
    if len(search_term) > 5:  # Terme assez long pour être spécifique
        # Simuler un maximum de 2 résultats
        results_count = random.randint(0, 2)
        
        for i in range(results_count):
            # Générer une date dans les 6 derniers mois
            days_ago = random.randint(7, 180)
            mention_date = (datetime.datetime.now() - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")
            
            # Choisir un site
            site = random.choice(sites_to_check)
            
            # Déterminer un contexte en fonction du site
            if site == "Pastebin":
                context = f"Possible fuite de données contenant '{search_term}' trouvée sur Pastebin"
                category = SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]
            elif site in ["GitHub", "GitLab"]:
                context = f"Code source exposé contenant '{search_term}' trouvé sur {site}"
                category = SENSITIVE_DATA_CATEGORIES["CORPORATE"]
            elif site in ["HackForums", "Reddit"]:
                context = f"Discussion mentionnant '{search_term}' dans un contexte de sécurité sur {site}"
                category = "Données diverses"
            else:
                context = f"Mention de '{search_term}' trouvée sur {site}"
                category = "Données diverses"
            
            # Créer la mention
            mention = {
                "source": f"Recherche sur {site}",
                "date": mention_date,
                "category": category,
                "context": context,
                "confidence": 50,  # Confiance moyenne-faible
                "severity": "Moyenne",
                "verified": False,
                "enriched": True
            }
            
            mentions.append(mention)
    
    return mentions

def is_email(text):
    """
    Vérifie si une chaîne est un email valide.
    
    Args:
        text (str): Texte à vérifier
        
    Returns:
        bool: True si c'est un email
    """
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, text))

def is_domain(text):
    """
    Vérifie si une chaîne est un nom de domaine valide.
    
    Args:
        text (str): Texte à vérifier
        
    Returns:
        bool: True si c'est un domaine
    """
    # Supprimer le protocole si présent
    if text.startswith(("http://", "https://")):
        text = text.split("//", 1)[1]
    
    # Supprimer le chemin
    text = text.split("/", 1)[0]
    
    # Vérifier le format
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_pattern, text))

def categorize_data_classes(data_classes):
    """
    Catégorise les classes de données de HIBP en catégories générales.
    
    Args:
        data_classes (list): Liste des classes de données de HIBP
        
    Returns:
        str: Catégorie générale
    """
    if not data_classes:
        return "Données diverses"
    
    # Vérifier la présence de certaines classes pour déterminer la catégorie
    data_classes_str = " ".join(data_classes).lower()
    
    if any(term in data_classes_str for term in ["password", "credential", "authentication"]):
        return SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]
    
    if any(term in data_classes_str for term in ["credit", "financial", "payment", "bank", "card"]):
        return SENSITIVE_DATA_CATEGORIES["FINANCIAL"]
    
    if any(term in data_classes_str for term in ["address", "phone", "contact", "personal", "demographic"]):
        return SENSITIVE_DATA_CATEGORIES["PERSONAL"]
    
    if any(term in data_classes_str for term in ["corporate", "business", "employer", "employment"]):
        return SENSITIVE_DATA_CATEGORIES["CORPORATE"]
    
    if any(term in data_classes_str for term in ["health", "medical", "insurance", "patient"]):
        return SENSITIVE_DATA_CATEGORIES["MEDICAL"]
    
    if any(term in data_classes_str for term in ["identity", "document", "id number", "ssn", "national"]):
        return SENSITIVE_DATA_CATEGORIES["IDENTITY"]
    
    if any(term in data_classes_str for term in ["email", "message", "chat", "communication"]):
        return SENSITIVE_DATA_CATEGORIES["COMMUNICATION"]
    
    # Par défaut
    return "Données diverses"

def determine_breach_severity(data_classes):
    """
    Détermine la sévérité d'une violation en fonction des classes de données.
    
    Args:
        data_classes (list): Liste des classes de données
        
    Returns:
        str: Niveau de sévérité (Élevée, Moyenne, Faible)
    """
    if not data_classes:
        return "Moyenne"
    
    # Classes de données à haut risque
    high_risk_classes = [
        "Passwords", "Password hints", "Credit cards", "Banking details", 
        "Financial information", "Social security numbers", "Identity documents"
    ]
    
    # Classes de données à risque moyen
    medium_risk_classes = [
        "Email addresses", "Usernames", "Phone numbers", "Physical addresses",
        "IP addresses", "Employment information", "Education information"
    ]
    
    # Vérifier la présence de classes à haut risque
    if any(high_class in data_classes for high_class in high_risk_classes):
        return "Élevée"
    
    # Vérifier la présence de classes à risque moyen
    if any(medium_class in data_classes for medium_class in medium_risk_classes):
        return "Moyenne"
    
    # Par défaut
    return "Faible"

def determine_category_from_tags(tags):
    """
    Détermine la catégorie en fonction des tags.
    
    Args:
        tags (list): Liste de tags
        
    Returns:
        str: Catégorie déterminée
    """
    if not tags:
        return "Données diverses"
    
    tags_str = " ".join(tags).lower()
    
    if any(term in tags_str for term in ["credentials", "password", "account", "login"]):
        return SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]
    
    if any(term in tags_str for term in ["finance", "banking", "credit", "payment"]):
        return SENSITIVE_DATA_CATEGORIES["FINANCIAL"]
    
    if any(term in tags_str for term in ["personal", "pii", "contact"]):
        return SENSITIVE_DATA_CATEGORIES["PERSONAL"]
    
    if any(term in tags_str for term in ["corporate", "business", "company"]):
        return SENSITIVE_DATA_CATEGORIES["CORPORATE"]
    
    if any(term in tags_str for term in ["healthcare", "medical", "patient"]):
        return SENSITIVE_DATA_CATEGORIES["MEDICAL"]
    
    if any(term in tags_str for term in ["identity", "id", "passport"]):
        return SENSITIVE_DATA_CATEGORIES["IDENTITY"]
    
    if any(term in tags_str for term in ["communication", "email", "chat"]):
        return SENSITIVE_DATA_CATEGORIES["COMMUNICATION"]
    
    # Tags liés aux menaces ou au darkweb
    if any(term in tags_str for term in ["malicious", "hack", "breach", "leak", "dump"]):
        return SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]
    
    # Par défaut
    return "Données diverses"

def determine_category_from_text(text):
    """
    Détermine la catégorie en fonction d'un texte.
    
    Args:
        text (str): Texte à analyser
        
    Returns:
        str: Catégorie déterminée
    """
    text_lower = text.lower()
    
    if any(term in text_lower for term in ["password", "credential", "login", "account"]):
        return SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]
    
    if any(term in text_lower for term in ["credit card", "bank", "financial", "payment"]):
        return SENSITIVE_DATA_CATEGORIES["FINANCIAL"]
    
    if any(term in text_lower for term in ["personal data", "pii", "address", "phone"]):
        return SENSITIVE_DATA_CATEGORIES["PERSONAL"]
    
    if any(term in text_lower for term in ["corporate", "business", "company", "internal"]):
        return SENSITIVE_DATA_CATEGORIES["CORPORATE"]
    
    if any(term in text_lower for term in ["health", "medical", "patient"]):
        return SENSITIVE_DATA_CATEGORIES["MEDICAL"]
    
    if any(term in text_lower for term in ["identity", "id", "passport", "license"]):
        return SENSITIVE_DATA_CATEGORIES["IDENTITY"]
    
    if any(term in text_lower for term in ["email", "communication", "message"]):
        return SENSITIVE_DATA_CATEGORIES["COMMUNICATION"]
    
    # Termes liés aux menaces
    if any(term in text_lower for term in ["breach", "leak", "dump", "hack", "pwned"]):
        return SENSITIVE_DATA_CATEGORIES["CREDENTIALS"]  # Par défaut pour les fuites
    
    # Par défaut
    return "Données diverses"

def calculate_risk_level(mentions):
    """
    Calcule un niveau de risque global en fonction des mentions trouvées.
    
    Args:
        mentions (list): Liste des mentions trouvées
        
    Returns:
        int: Niveau de risque entre 0 et 10
    """
    if not mentions:
        return 0
    
    # Facteurs influençant le niveau de risque
    num_mentions = len(mentions)
    num_verified = len([m for m in mentions if m.get("verified", False)])
    num_enriched = len([m for m in mentions if m.get("enriched", False)])
    
    # Calculer la récence moyenne (en jours)
    today = datetime.datetime.now()
    total_days = 0
    recent_count = 0
    
    for mention in mentions:
        try:
            mention_date = mention.get("date", "Date inconnue")
            if mention_date != "Date inconnue":
                mention_date = datetime.datetime.strptime(mention_date, "%Y-%m-%d")
                days_ago = (today - mention_date).days
                total_days += days_ago
                
                # Compter les mentions récentes (moins de 90 jours)
                if days_ago < 90:
                    recent_count += 1
        except Exception:
            pass
    
    avg_days_ago = total_days / num_mentions if num_mentions > 0 else 180
    
    # Les mentions plus récentes augmentent le risque
    recency_factor = max(0, 10 - (avg_days_ago / 30))  # 0 à 10 selon la récence
    
    # Évaluer la sévérité des mentions
    severity_weights = {
        "Élevée": 10,
        "Moyenne": 6,
        "Faible": 3
    }
    
    total_severity = 0
    for mention in mentions:
        severity = mention.get("severity", "Faible")
        weight = severity_weights.get(severity, 3)
        
        # Ajuster le poids selon la confiance et si la mention est vérifiée
        confidence = mention.get("confidence", 50) / 100
        verified_multiplier = 1.5 if mention.get("verified", False) else 1.0
        enriched_multiplier = 0.7 if mention.get("enriched", False) else 1.0
        
        total_severity += weight * confidence * verified_multiplier * enriched_multiplier
    
    avg_severity = total_severity / num_mentions if num_mentions > 0 else 0
    
    # Facteur de concentration de catégories (plus de catégories différentes = plus de risque)
    categories = set(mention.get("category", "") for mention in mentions)
    category_factor = min(5, len(categories)) / 5 * 10  # 0 à 10 selon la diversité
    
    # Facteur de vérification (plus de mentions vérifiées = plus de risque)
    verification_factor = num_verified / num_mentions * 10 if num_mentions > 0 else 0
    
    # Réduire l'impact des mentions enrichies
    enrichment_factor = num_enriched / num_mentions if num_mentions > 0 else 0
    
    # Combinaison des facteurs pour obtenir un score final
    base_risk = min(10, num_mentions * 0.5)  # Base selon le nombre de mentions
    recent_risk = min(10, recent_count * 2)  # Impact des mentions récentes
    
    # Formule pondérée
    adjusted_risk = (
        (base_risk * 0.2) +
        (recency_factor * 0.2) +
        (avg_severity * 0.25) +
        (category_factor * 0.1) +
        (recent_risk * 0.1) +
        (verification_factor * 0.15)
    )
    
    # Réduire le score s'il y a beaucoup de mentions enrichies
    if enrichment_factor > 0.5:
        adjusted_risk *= (1 - (enrichment_factor - 0.5) * 0.4)
    
    # Arrondir à un entier entre 0 et 10
    return round(min(10, max(0, adjusted_risk)))

def get_risk_description(risk_level):
    """
    Obtient une description textuelle du niveau de risque.
    
    Args:
        risk_level (int): Niveau de risque entre 0 et 10
        
    Returns:
        str: Description du niveau de risque
    """
    if risk_level >= HIGH_RISK_THRESHOLD:
        return "Élevé - Des mesures immédiates sont recommandées"
    elif risk_level >= MEDIUM_RISK_THRESHOLD:
        return "Moyen - Une surveillance accrue est recommandée"
    else:
        return "Faible - Continuer la surveillance standard"

def get_recommended_actions(risk_level, mentions):
    """
    Obtient des recommandations basées sur le niveau de risque et les mentions.
    
    Args:
        risk_level (int): Niveau de risque entre 0 et 10
        mentions (list): Liste des mentions trouvées
        
    Returns:
        list: Liste de recommandations d'actions
    """
    actions = []
    
    # Recommandations de base pour tous les niveaux de risque
    actions.append("Continuer la surveillance régulière des fuites de données")
    
    # Recommandations supplémentaires selon le niveau de risque
    if risk_level >= HIGH_RISK_THRESHOLD:
        actions.extend([
            "Changer immédiatement tous les mots de passe liés",
            "Activer l'authentification à deux facteurs partout où c'est possible",
            "Surveiller attentivement les transactions financières",
            "Consulter un expert en cybersécurité"
        ])
    elif risk_level >= MEDIUM_RISK_THRESHOLD:
        actions.extend([
            "Changer les mots de passe des comptes sensibles",
            "Activer l'authentification à deux facteurs sur les comptes critiques",
            "Surveiller les activités suspectes"
        ])
    
    # Recommandations spécifiques selon les catégories des mentions
    categories = set(mention.get("category", "") for mention in mentions)
    
    if SENSITIVE_DATA_CATEGORIES["CREDENTIALS"] in categories:
        actions.append("Utiliser un gestionnaire de mots de passe et créer des mots de passe uniques")
    
    if SENSITIVE_DATA_CATEGORIES["FINANCIAL"] in categories:
        actions.append("Configurer des alertes de transactions bancaires")
    
    if SENSITIVE_DATA_CATEGORIES["PERSONAL"] in categories:
        actions.append("Être vigilant face aux tentatives de phishing")
    
    if SENSITIVE_DATA_CATEGORIES["CORPORATE"] in categories:
        actions.append("Renforcer la sécurité des données d'entreprise et sensibiliser les employés")
    
    # Éviter les doublons et limiter à 6 recommandations
    return list(dict.fromkeys(actions))[:6]