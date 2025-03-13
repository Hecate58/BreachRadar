#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import re
from config import HIBP_API_KEY, API_TIMEOUT

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# API URLs
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_BREACH_URL = f"{HIBP_BASE_URL}/breachedaccount"
HIBP_DOMAIN_URL = f"{HIBP_BASE_URL}/breaches"

# Headers requis pour l'API HaveIBeenPwned
HIBP_HEADERS = {
    "hibp-api-key": HIBP_API_KEY,
    "User-Agent": "Cybersecurity-Telegram-Bot"
}

def is_valid_email(email):
    """Vérifie si une chaîne est un email valide."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def is_valid_domain(domain):
    """Vérifie si une chaîne est un nom de domaine valide."""
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))

def check_breaches(input_data):
    """
    Vérifie les violations de données pour un email ou un domaine.
    
    Args:
        input_data (str): Email ou domaine à vérifier
        
    Returns:
        list: Liste des violations trouvées avec leurs détails
    """
    try:
        if is_valid_email(input_data):
            # Recherche de violations pour un email
            return check_email_breaches(input_data)
        elif is_valid_domain(input_data):
            # Recherche de violations pour un domaine
            return check_domain_breaches(input_data)
        else:
            logger.warning(f"Format invalide: {input_data}")
            return []
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des violations: {e}")
        return []

def check_email_breaches(email):
    """
    Vérifie les violations de données pour un email spécifique.
    
    Args:
        email (str): Adresse email à vérifier
        
    Returns:
        list: Liste des violations trouvées pour cet email
    """
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
            return format_breach_results(breaches)
        elif response.status_code == 404:
            # Aucune violation trouvée
            return []
        else:
            logger.error(f"Erreur API HIBP: {response.status_code} - {response.text}")
            return []
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur de requête pour l'email {email}: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de décodage JSON pour l'email {email}: {e}")
        return []

def check_domain_breaches(domain):
    """
    Vérifie les violations de données pour un domaine spécifique.
    
    Args:
        domain (str): Nom de domaine à vérifier
        
    Returns:
        list: Liste des violations trouvées pour ce domaine
    """
    try:
        # Effectuer la requête à l'API
        response = requests.get(
            HIBP_DOMAIN_URL,
            headers=HIBP_HEADERS,
            timeout=API_TIMEOUT
        )
        
        # Traiter la réponse
        if response.status_code == 200:
            all_breaches = response.json()
            
            # Filtrer les violations spécifiques au domaine
            domain_breaches = [
                breach for breach in all_breaches
                if domain.lower() in breach.get("Domain", "").lower()
            ]
            
            return format_breach_results(domain_breaches)
        else:
            logger.error(f"Erreur API HIBP: {response.status_code} - {response.text}")
            return []
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur de requête pour le domaine {domain}: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de décodage JSON pour le domaine {domain}: {e}")
        return []

def format_breach_results(breaches):
    """
    Formate les résultats des violations pour une utilisation facile.
    
    Args:
        breaches (list): Liste des violations brutes de l'API
        
    Returns:
        list: Liste formatée des violations avec les informations pertinentes
    """
    formatted_results = []
    
    for breach in breaches:
        # Extraire les classes de données en une chaîne lisible
        data_classes = ", ".join(breach.get("DataClasses", []))
        
        # Formater la date
        breach_date = breach.get("BreachDate", "Date inconnue")
        
        formatted_breach = {
            "name": breach.get("Name", "Violation inconnue"),
            "domain": breach.get("Domain", ""),
            "date": breach_date,
            "data_classes": data_classes,
            "description": breach.get("Description", ""),
            "pwn_count": breach.get("PwnCount", 0),
            "is_verified": breach.get("IsVerified", False),
            "is_sensitive": breach.get("IsSensitive", False),
            "logo_url": breach.get("LogoPath", "")
        }
        
        formatted_results.append(formatted_breach)
    
    # Trier les résultats par date (plus récent d'abord)
    return sorted(formatted_results, key=lambda x: x["date"], reverse=True)