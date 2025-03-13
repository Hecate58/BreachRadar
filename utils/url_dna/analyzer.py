#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import socket
import ssl
import requests
import tldextract
import logging
import datetime
import urllib.parse
from config import VIRUSTOTAL_API_KEY, API_TIMEOUT
import utils.whois as whois

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Constantes pour les API
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"

def analyze_url(url):
    """
    Analyse une URL pour détecter des menaces potentielles.
    
    Args:
        url (str): URL à analyser
        
    Returns:
        dict: Résultats de l'analyse avec le niveau de sécurité et les alertes
    """
    logger.info(f"Analyse de l'URL: {url}")
    
    # Nettoyer et normaliser l'URL
    url = clean_url(url)
    
    # Initialiser le résultat
    result = {
        "url": url,
        "safe": True,
        "reputation_score": 100,
        "ssl_valid": None,
        "domain_age": "Inconnu",
        "alerts": []
    }
    
    try:
        # 1. Extraire le domaine
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # 2. Vérifier l'âge du domaine
        result["domain_age"] = get_domain_age(domain)
        
        # 3. Vérifier la validité du certificat SSL
        result["ssl_valid"] = check_ssl(url)
        
        # 4. Vérifier les caractéristiques suspectes de l'URL
        check_suspicious_url_features(url, result)
        
        # 5. Vérifier avec VirusTotal si l'API key est disponible
        if VIRUSTOTAL_API_KEY:
            check_virustotal(url, result)
        
        # 6. Simuler la vérification avec PhishTank
        check_phishing_patterns(url, domain, result)
        
        # Déterminer si l'URL est sûre en fonction du nombre d'alertes
        if len(result["alerts"]) > 0:
            result["safe"] = False
            # Réduire le score de réputation en fonction du nombre et de la gravité des alertes
            result["reputation_score"] = max(0, 100 - (len(result["alerts"]) * 20))
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'URL {url}: {e}")
        result["alerts"].append(f"Erreur lors de l'analyse: {str(e)}")
        result["safe"] = False
        result["reputation_score"] = 0
    
    return result

def clean_url(url):
    """
    Nettoie et normalise une URL.
    
    Args:
        url (str): URL à nettoyer
        
    Returns:
        str: URL nettoyée
    """
    # S'assurer que l'URL commence par un protocole
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url

def get_domain_age(domain):
    """
    Obtient l'âge du domaine à partir des informations WHOIS.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        str: Âge du domaine sous forme lisible
    """
    try:
        return whois.get_domain_age(domain)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'âge du domaine {domain}: {e}")
        return "Inconnu"

def check_ssl(url):
    """
    Vérifie la validité du certificat SSL d'une URL.
    
    Args:
        url (str): URL à vérifier
        
    Returns:
        bool: True si le certificat SSL est valide, False sinon
    """
    if not url.startswith('https://'):
        return False
    
    try:
        domain = urllib.parse.urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=API_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Si aucune exception n'est levée, le certificat est valide
                return True
    except Exception as e:
        logger.warning(f"Erreur SSL pour {url}: {e}")
        return False

def check_suspicious_url_features(url, result):
    """
    Vérifie les caractéristiques suspectes d'une URL.
    
    Args:
        url (str): URL à vérifier
        result (dict): Dictionnaire de résultats à mettre à jour
    """
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # 1. Vérifier la présence d'adresses IP
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        result["alerts"].append("L'URL utilise une adresse IP au lieu d'un nom de domaine.")
    
    # 2. Vérifier les sous-domaines excessifs
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count > 3:
        result["alerts"].append("L'URL contient un nombre inhabituellement élevé de sous-domaines.")
    
    # 3. Vérifier les caractères suspects dans le domaine
    if re.search(r'[^a-zA-Z0-9\-\.]', domain):
        result["alerts"].append("Le domaine contient des caractères inhabituels.")
    
    # 4. Vérifier la présence de termes sensibles (banques, paiements, etc.)
    sensitive_terms = ['paypal', 'bank', 'secure', 'login', 'account', 'verify', 'update', 'apple', 
                      'microsoft', 'google', 'facebook', 'amazon', 'netflix', 'signin', 'security']
    
    domain_lower = domain.lower()
    for term in sensitive_terms:
        if term in domain_lower and not domain_lower.endswith(f"{term}.com"):
            result["alerts"].append(f"Le domaine contient le terme sensible '{term}' et pourrait être une tentative d'usurpation.")
            break
    
    # 5. Vérifier les redirections dans l'URL
    if '@' in url:
        result["alerts"].append("L'URL contient le caractère '@' qui peut être utilisé pour des redirections malveillantes.")
    
    # 6. Vérifier la longueur excessive de l'URL
    if len(url) > 100:
        result["alerts"].append("L'URL est inhabituellement longue.")
    
    # 7. Vérifier les paramètres de requête suspects
    query_params = urllib.parse.parse_qs(parsed_url.query)
    suspicious_params = ['pass', 'pwd', 'password', 'ssn', 'cc', 'creditcard', 'card', 'cvv', 'pin']
    
    for param in query_params:
        if param.lower() in suspicious_params:
            result["alerts"].append(f"L'URL contient le paramètre sensible '{param}' dans sa requête.")
            break

def check_virustotal(url, result):
    """
    Vérifie l'URL avec l'API VirusTotal.
    
    Args:
        url (str): URL à vérifier
        result (dict): Dictionnaire de résultats à mettre à jour
    """
    try:
        # Encoder l'URL pour la requête
        encoded_url = urllib.parse.quote_plus(url)
        
        # Créer les headers avec la clé API
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Soumettre l'URL pour analyse
        data = f"url={encoded_url}"
        response = requests.post(
            VIRUSTOTAL_URL,
            headers=headers,
            data=data,
            timeout=API_TIMEOUT
        )
        
        if response.status_code == 200:
            submission_data = response.json()
            analysis_id = submission_data.get("data", {}).get("id")
            
            if analysis_id:
                # Attendre un moment et récupérer les résultats
                url_report_endpoint = f"{VIRUSTOTAL_URL}/{analysis_id}"
                report_response = requests.get(
                    url_report_endpoint,
                    headers=headers,
                    timeout=API_TIMEOUT
                )
                
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    attributes = report_data.get("data", {}).get("attributes", {})
                    stats = attributes.get("stats", {})
                    
                    # Vérifier les résultats
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    if malicious > 0:
                        result["alerts"].append(f"L'URL a été signalée comme malveillante par {malicious} moteurs de détection.")
                    
                    if suspicious > 0:
                        result["alerts"].append(f"L'URL a été signalée comme suspecte par {suspicious} moteurs de détection.")
                    
                    # Mettre à jour le score de réputation
                    total_engines = sum(stats.values())
                    if total_engines > 0:
                        harmless = stats.get("harmless", 0)
                        reputation_score = int((harmless / total_engines) * 100)
                        result["reputation_score"] = reputation_score
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification VirusTotal pour {url}: {e}")

def check_phishing_patterns(url, domain, result):
    """
    Vérifie les motifs de phishing courants.
    
    Args:
        url (str): URL à vérifier
        domain (str): Domaine extrait de l'URL
        result (dict): Dictionnaire de résultats à mettre à jour
    """
    # Simuler la détection de patterns de phishing
    
    # 1. Vérifier si le domaine est récemment créé (moins de 90 jours)
    is_recent = whois.is_domain_recently_created(domain)
    if is_recent:
        result["alerts"].append("Le domaine a été créé récemment, ce qui peut être un indicateur de phishing.")
    
    # 2. Vérifier les URL de type "typosquatting" (fautes de frappe de domaines populaires)
    popular_domains = [
        ('google', 'gooogle', 'googel', 'gogle'),
        ('facebook', 'faceboook', 'facbook', 'facebuk'),
        ('amazon', 'amazone', 'amazom', 'amason'),
        ('paypal', 'paypaI', 'paypall', 'paypaI', 'paypol'),
        ('microsoft', 'microsft', 'mircosoft', 'macrosoft'),
        ('apple', 'appIe', 'aple', 'appel')
    ]
    
    domain_lower = domain.lower()
    for original, *typos in popular_domains:
        if domain_lower not in [original] and any(typo in domain_lower for typo in typos):
            result["alerts"].append(f"Le domaine ressemble à une faute de frappe de '{original}', possible tentative de typosquatting.")
            break
    
    # 3. Vérifier la présence de mots-clés suspects dans l'URL
    suspicious_keywords = [
        'secure', 'login', 'signin', 'verify', 'update', 'confirm', 'account',
        'banking', 'password', 'credential', 'authenticate', 'session'
    ]
    
    keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
    if keyword_count >= 3:
        result["alerts"].append(f"L'URL contient plusieurs mots-clés associés aux tentatives de phishing.")
    
    # 4. Vérifier les URL avec des chaînes d'authentification suspectes
    if re.search(r'auth|token|session|login|signin', url.lower()) and re.search(r'[a-zA-Z0-9]{10,}', url):
        result["alerts"].append("L'URL contient des chaînes d'authentification suspectes.")