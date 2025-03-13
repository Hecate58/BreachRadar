#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import re
import urllib.parse
import ssl
import socket
import tldextract
import datetime
import fix_whois as whois_lib
from config import VIRUSTOTAL_API_KEY, API_TIMEOUT

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Liste de mots souvent utilisés dans les URLs de phishing
PHISHING_KEYWORDS = [
    'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 
    'banking', 'confirm', 'update', 'verify', 'login', 'paypal',
    'password', 'credential', 'wallet', 'verification', 'authenticate',
    'recovery', 'authorize', 'validation'
]

# Pattern de caractères suspects dans les URLs
SUSPICIOUS_PATTERNS = [
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP address
    r'(https?://)?\d+\.\d+\.\d+\.\d+',  # IP with http
    r'[a-zA-Z0-9]{25,}',  # Long random strings
    r'(paypal|apple|google|facebook|microsoft|amazon).*?\.(?!com|net|org)',  # Typosquatting
    r'\.tk$|\.ga$|\.cf$|\.ml$|\.gq$',  # Free domains often used for phishing
]

# Domaines de marques souvent usurpés
POPULAR_BRANDS = [
    'google', 'facebook', 'apple', 'amazon', 'microsoft', 'paypal', 'netflix',
    'linkedin', 'twitter', 'instagram', 'bank', 'wellsfargo', 'bankofamerica',
    'chase', 'amex', 'american express'
]

# Configuration de l'API VirusTotal
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

def analyze_url(url):
    """
    Analyse complète d'une URL pour détecter des menaces potentielles.
    
    Args:
        url (str): URL à analyser
        
    Returns:
        dict: Résultat de l'analyse avec des détails sur les risques
    """
    logger.info(f"Analyse de l'URL: {url}")
    
    # Normaliser l'URL
    normalized_url = normalize_url(url)
    
    # Extraire les composants de l'URL
    parsed_url = urllib.parse.urlparse(normalized_url)
    domain = parsed_url.netloc
    
    # Initialiser le dictionnaire de résultats
    results = {
        "url": normalized_url,
        "domain": domain,
        "safe": True,
        "alerts": [],
        "reputation_score": 100,  # Score initial (va être réduit si des risques sont détectés)
        "ssl_valid": False,
        "domain_age": "Inconnu",
        "analysis_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Analyse de la structure de l'URL
    url_structure_score, url_alerts = analyze_url_structure(normalized_url)
    results["alerts"].extend(url_alerts)
    
    # Vérification SSL
    ssl_valid, ssl_alerts = check_ssl_certificate(domain)
    results["ssl_valid"] = ssl_valid
    results["alerts"].extend(ssl_alerts)
    
    # Analyse du nom de domaine
    domain_score, domain_alerts, domain_age = analyze_domain(domain)
    results["domain_age"] = domain_age
    results["alerts"].extend(domain_alerts)
    
    # Vérification via VirusTotal (si l'API key est configurée)
    if VIRUSTOTAL_API_KEY:
        vt_score, vt_alerts = check_virustotal(normalized_url)
        results["alerts"].extend(vt_alerts)
    else:
        vt_score = 0
        logger.warning("Clé API VirusTotal non configurée, vérification ignorée")
    
    # Calculer le score de réputation final
    # On donne des poids différents à chaque type d'analyse
    reputation_score = (
        (url_structure_score * 0.3) +
        (domain_score * 0.3) +
        (vt_score * 0.4)
    )
    
    # Si le certificat SSL est invalide, on pénalise davantage
    if not ssl_valid:
        reputation_score = max(0, reputation_score - 20)
    
    # Arrondir le score
    results["reputation_score"] = round(reputation_score)
    
    # Décider si l'URL est sûre en fonction du score et des alertes
    if reputation_score < 60 or len(results["alerts"]) > 2:
        results["safe"] = False
    
    return results

def normalize_url(url):
    """
    Normalise une URL pour l'analyse.
    
    Args:
        url (str): URL à normaliser
        
    Returns:
        str: URL normalisée
    """
    # S'assurer que l'URL commence par un protocole
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Normaliser l'URL
    parsed = urllib.parse.urlparse(url)
    
    # Reconstruire l'URL avec les composants normalisés
    normalized = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
    return normalized

def analyze_url_structure(url):
    """
    Analyse la structure d'une URL pour détecter des signes suspects.
    
    Args:
        url (str): URL à analyser
        
    Returns:
        tuple: Score de l'analyse (0-100) et liste d'alertes
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    alerts = []
    score = 100  # Score initial (on retire des points pour chaque alerte)
    
    # Vérifier la présence d'adresse IP au lieu d'un nom de domaine
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        alerts.append("L'URL utilise une adresse IP directe au lieu d'un nom de domaine")
        score -= 30
    
    # Vérifier la présence de mots-clés de phishing dans l'URL
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain.lower() or keyword in path.lower():
            alerts.append(f"L'URL contient le mot-clé suspect '{keyword}'")
            score -= 5
            break  # Ne pénaliser qu'une fois pour les mots-clés
    
    # Vérifier les motifs suspects
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            alerts.append("L'URL contient un motif suspect")
            score -= 15
            break  # Ne pénaliser qu'une fois pour les motifs suspects
    
    # Vérifier la longueur du domaine (les domaines très longs sont suspects)
    if len(domain) > 30:
        alerts.append("Le nom de domaine est anormalement long")
        score -= 10
    
    # Vérifier si l'URL contient trop de sous-domaines
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        alerts.append("L'URL contient un nombre suspect de sous-domaines")
        score -= 10
    
    # Vérifier la présence de caractères Unicode trompeurs
    if any(ord(c) > 127 for c in domain):
        alerts.append("Le domaine contient des caractères Unicode potentiellement trompeurs")
        score -= 25
    
    # Vérifier si l'URL contient des éléments d'authentification suspects
    if re.search(r'user|pass|login|pwd|token|key', query, re.IGNORECASE):
        alerts.append("L'URL contient des paramètres d'authentification en clair")
        score -= 15
    
    # Limiter le score entre 0 et 100
    score = max(0, min(100, score))
    
    return score, alerts

def check_ssl_certificate(domain):
    """
    Vérifie la validité du certificat SSL d'un domaine.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        tuple: Booléen indiquant si le certificat est valide et liste d'alertes
    """
    alerts = []
    
    # Si le domaine contient un port, le supprimer pour la vérification SSL
    if ':' in domain:
        domain = domain.split(':')[0]
    
    try:
        # Configurer le contexte SSL
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=API_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Vérifier la date d'expiration
                expires = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                
                if now > expires:
                    alerts.append("Le certificat SSL a expiré")
                    return False, alerts
                
                # Vérifier l'autorité de certification
                issuer = dict(x[0] for x in cert['issuer'])
                if 'organizationName' not in issuer:
                    alerts.append("Le certificat SSL provient d'une autorité non identifiée")
                    return False, alerts
                
                return True, []
                
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        # Le domaine ne supporte pas HTTPS ou n'existe pas
        alerts.append("Le domaine ne supporte pas HTTPS ou n'existe pas")
        return False, alerts
    except ssl.SSLError:
        # Certificat invalide
        alerts.append("Le certificat SSL est invalide")
        return False, alerts
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du certificat SSL: {e}")
        alerts.append("Impossible de vérifier le certificat SSL")
        return False, alerts

def analyze_domain(domain):
    """
    Analyse un nom de domaine pour détecter des signes de phishing ou d'abus.
    
    Args:
        domain (str): Domaine à analyser
        
    Returns:
        tuple: Score de l'analyse (0-100), liste d'alertes et âge du domaine
    """
    alerts = []
    score = 100  # Score initial
    domain_age = "Inconnu"
    
    # Si le domaine contient un port, le supprimer pour l'analyse
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Extraire les parties du domaine
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    tld = extracted.suffix
    
    # Vérifier si le domaine est un TLD gratuit ou rare souvent utilisé pour les abus
    suspicious_tlds = ['tk', 'ga', 'cf', 'ml', 'gq', 'xyz', 'top', 'country', 'stream', 'bid']
    if tld in suspicious_tlds or any(tld.endswith('.' + s) for s in suspicious_tlds):
        alerts.append(f"Le domaine utilise un TLD suspect (.{tld})")
        score -= 15
    
    # Vérifier si le domaine contient des marques populaires mais n'est pas le domaine officiel
    for brand in POPULAR_BRANDS:
        if brand in domain_name.lower() and not is_official_domain(domain, brand):
            alerts.append(f"Le domaine semble usurper la marque '{brand}'")
            score -= 25
            break
    
    # Vérifier l'âge du domaine avec WHOIS
    try:
        domain_info = whois_lib.whois(domain)
        
        # Vérifier si le domaine existe
        if domain_info.status is None:
            alerts.append("Le domaine n'est pas enregistré")
            score -= 50
            domain_age = "Non enregistré"
        else:
            # Calculer l'âge du domaine
            creation_date = domain_info.creation_date
            
            # Gérer les cas où creation_date est une liste
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                now = datetime.datetime.now()
                age_days = (now - creation_date).days
                
                if age_days < 30:
                    alerts.append("Le domaine a été créé très récemment (moins de 30 jours)")
                    score -= 30
                    domain_age = f"{age_days} jours"
                elif age_days < 90:
                    alerts.append("Le domaine a été créé récemment (moins de 3 mois)")
                    score -= 15
                    domain_age = f"{age_days // 30} mois"
                else:
                    domain_age = f"{age_days // 365} ans et {(age_days % 365) // 30} mois"
            else:
                domain_age = "Inconnu"
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification WHOIS: {e}")
        domain_age = "Erreur de vérification"
    
    # Limiter le score entre 0 et 100
    score = max(0, min(100, score))
    
    return score, alerts, domain_age

def is_official_domain(domain, brand):
    """
    Vérifie si un domaine est le domaine officiel d'une marque.
    
    Args:
        domain (str): Domaine à vérifier
        brand (str): Nom de la marque
        
    Returns:
        bool: True si le domaine semble être officiel
    """
    # Mapping simplifié des domaines officiels de certaines marques
    official_domains = {
        'google': ['google.com', 'google.co.uk', 'google.fr', 'google.de', 'googleapis.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'apple': ['apple.com', 'icloud.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.fr'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com'],
        'paypal': ['paypal.com', 'paypal.me'],
        'netflix': ['netflix.com'],
        'linkedin': ['linkedin.com'],
        'twitter': ['twitter.com', 'x.com'],
        'instagram': ['instagram.com']
    }
    
    # Extraire les parties du domaine
    extracted = tldextract.extract(domain)
    full_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Vérifier si c'est un domaine officiel connu
    if brand in official_domains:
        return full_domain in official_domains[brand]
    
    # Pour les marques non listées, vérifier si le domaine correspond exactement
    return full_domain == f"{brand}.com"

def check_virustotal(url):
    """
    Vérifie une URL via l'API VirusTotal.
    
    Args:
        url (str): URL à vérifier
        
    Returns:
        tuple: Score de l'analyse (0-100) et liste d'alertes
    """
    alerts = []
    
    try:
        # Soumettre l'URL à VirusTotal
        data = {"url": url}
        response = requests.post(
            VT_API_URL,
            headers=VT_HEADERS,
            data=data,
            timeout=API_TIMEOUT
        )
        
        if response.status_code != 200:
            logger.error(f"Erreur de l'API VirusTotal: {response.status_code} - {response.text}")
            return 50, []  # Score neutre en cas d'erreur
        
        # Extraire l'ID d'analyse
        analysis_id = response.json().get("data", {}).get("id")
        
        if not analysis_id:
            logger.error("Impossible d'obtenir l'ID d'analyse de VirusTotal")
            return 50, []
        
        # Obtenir les résultats de l'analyse
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_response = requests.get(
            analysis_url,
            headers=VT_HEADERS,
            timeout=API_TIMEOUT
        )
        
        if result_response.status_code != 200:
            logger.error(f"Erreur lors de la récupération des résultats VirusTotal: {result_response.status_code}")
            return 50, []
        
        # Analyser les résultats
        results = result_response.json()
        attributes = results.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        
        # Calculer le score en fonction du nombre de détections
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        if total == 0:
            return 80, []  # Score relativement bon si aucun résultat
        
        # Calculer le pourcentage de détections négatives
        negative_percent = 100 * (malicious + suspicious) / total
        
        # Convertir en score (0-100, où 100 est sûr)
        score = max(0, 100 - negative_percent)
        
        # Ajouter des alertes si nécessaire
        if malicious > 0:
            alerts.append(f"VirusTotal: {malicious} moteurs de détection signalent cette URL comme malveillante")
        
        if suspicious > 0:
            alerts.append(f"VirusTotal: {suspicious} moteurs de détection signalent cette URL comme suspecte")
        
        return score, alerts
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification VirusTotal: {e}")
        return 50, []  # Score neutre en cas d'erreur