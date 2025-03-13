#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import datetime
import time
import re
import tldextract
import socket
import ssl
import dns.resolver
import utils.whois as whois
from urllib.parse import urlparse, urljoin
from config import API_TIMEOUT

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# En-têtes communs pour les requêtes
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1"
}

# Ports communs à scanner
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 8080, 8443]

# En-têtes de sécurité à vérifier
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Active la protection HSTS qui force les connexions HTTPS",
        "recommendation": "Ajouter l'en-tête 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
        "severity": "Moyenne"
    },
    "Content-Security-Policy": {
        "description": "Définit la politique de sécurité du contenu pour prévenir les attaques XSS",
        "recommendation": "Ajouter l'en-tête 'Content-Security-Policy' avec une configuration appropriée",
        "severity": "Moyenne"
    },
    "X-Content-Type-Options": {
        "description": "Empêche le navigateur d'interpréter les fichiers comme un type MIME différent",
        "recommendation": "Ajouter l'en-tête 'X-Content-Type-Options: nosniff'",
        "severity": "Faible"
    },
    "X-Frame-Options": {
        "description": "Protège contre le clickjacking en empêchant le site d'être affiché dans un iframe",
        "recommendation": "Ajouter l'en-tête 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN'",
        "severity": "Moyenne"
    },
    "X-XSS-Protection": {
        "description": "Active la protection XSS du navigateur",
        "recommendation": "Ajouter l'en-tête 'X-XSS-Protection: 1; mode=block'",
        "severity": "Faible"
    },
    "Referrer-Policy": {
        "description": "Contrôle les informations de référent envoyées lors de la navigation",
        "recommendation": "Ajouter l'en-tête 'Referrer-Policy: strict-origin-when-cross-origin'",
        "severity": "Faible"
    },
    "Permissions-Policy": {
        "description": "Contrôle quelles fonctionnalités et API peuvent être utilisées",
        "recommendation": "Ajouter l'en-tête 'Permissions-Policy' avec les restrictions appropriées",
        "severity": "Faible"
    }
}

# Liste des vulnérabilités courantes à vérifier
COMMON_VULNERABILITIES = {
    "heartbleed": {
        "name": "Heartbleed",
        "cve": "CVE-2014-0160",
        "description": "Vulnérabilité critique d'OpenSSL permettant de lire la mémoire d'un serveur vulnérable.",
        "severity": "Élevée",
        "check": lambda banner: "openssl" in banner.lower() and any(version in banner for version in ["1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"]),
        "recommendation": "Mettre à jour OpenSSL vers la dernière version stable."
    },
    "obsolete_php": {
        "name": "PHP obsolète",
        "description": "Version de PHP obsolète et non supportée qui peut contenir des vulnérabilités connues.",
        "severity": "Moyenne",
        "check": lambda banner: "php" in banner.lower() and any(version in banner for version in ["5.3.", "5.4.", "5.5.", "5.6.", "7.0.", "7.1."]),
        "recommendation": "Mettre à jour PHP vers une version supportée (7.4 ou supérieur)."
    },
    "obsolete_apache": {
        "name": "Apache obsolète",
        "description": "Version d'Apache obsolète et non supportée qui peut contenir des vulnérabilités connues.",
        "severity": "Moyenne",
        "check": lambda banner: "apache" in banner.lower() and any(version in banner for version in ["1.", "2.0.", "2.2."]),
        "recommendation": "Mettre à jour Apache vers la dernière version stable (2.4.x)."
    },
    "obsolete_nginx": {
        "name": "Nginx obsolète",
        "description": "Version de Nginx obsolète et non supportée qui peut contenir des vulnérabilités connues.",
        "severity": "Moyenne",
        "check": lambda banner: "nginx" in banner.lower() and any(version in banner for version in ["0.", "1.0.", "1.1.", "1.2.", "1.3.", "1.4.", "1.5.", "1.6.", "1.7.", "1.8.", "1.9.", "1.10.", "1.11.", "1.12.", "1.13.", "1.14.", "1.15.", "1.16."]),
        "recommendation": "Mettre à jour Nginx vers la dernière version stable."
    },
    "directory_listing": {
        "name": "Listage de répertoire activé",
        "description": "Le serveur permet le listage des répertoires, ce qui peut exposer des fichiers sensibles.",
        "severity": "Faible",
        "check": lambda banner: "Index of /" in banner,
        "recommendation": "Désactiver le listage des répertoires dans la configuration du serveur web."
    },
    "server_header": {
        "name": "En-tête Server exposé",
        "description": "Le serveur expose des informations détaillées sur sa version dans l'en-tête Server.",
        "severity": "Faible",
        "check": lambda banner: any(server in banner.lower() for server in ["apache", "nginx", "iis"]) and any(char.isdigit() for char in banner),
        "recommendation": "Configurer le serveur pour masquer les informations de version dans l'en-tête Server."
    },
    "weak_ssl": {
        "name": "Configuration SSL/TLS faible",
        "description": "Le serveur utilise des protocoles SSL/TLS obsolètes ou des suites de chiffrement faibles.",
        "severity": "Moyenne",
        "check": lambda banner: any(protocol in banner.lower() for protocol in ["sslv2", "sslv3", "tlsv1.0", "tlsv1.1"]),
        "recommendation": "Configurer le serveur pour utiliser uniquement TLS 1.2 ou supérieur et des suites de chiffrement fortes."
    },
    "cgi_enabled": {
        "name": "CGI activé",
        "description": "Le serveur a CGI activé, ce qui peut être exploité si des scripts CGI vulnérables sont présents.",
        "severity": "Moyenne",
        "check": lambda banner: "/cgi-bin/" in banner or "cgi-bin" in banner,
        "recommendation": "Désactiver CGI si non nécessaire ou limiter strictement l'accès aux scripts CGI."
    }
}

def scan_vulnerabilities(domain):
    """
    Analyse un domaine pour détecter des vulnérabilités connues.
    
    Args:
        domain (str): Domaine à analyser
        
    Returns:
        dict: Résultats de l'analyse avec les vulnérabilités détectées
    """
    logger.info(f"Analyse des vulnérabilités pour {domain}")
    
    # Nettoyer le domaine
    domain = clean_domain(domain)
    
    # Initialiser le dictionnaire de résultats
    results = {
        "domain": domain,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "risk_score": 0,
        "server_info": {
            "server": "Inconnu",
            "technologies": [],
            "ip_addresses": [],
            "ports": [],
            "last_updated": "N/A"
        }
    }
    
    try:
        # Récupérer les informations de base du serveur
        server_info = get_server_info(domain)
        if server_info:
            results["server_info"].update(server_info)
        
        # Vérifier les vulnérabilités courantes basées sur les informations du serveur
        custom_vulns = check_common_vulnerabilities(results["server_info"])
        results["vulnerabilities"].extend(custom_vulns)
        
        # Vérifier les problèmes de configuration SSL/TLS
        ssl_vulns = check_ssl_vulnerabilities(domain)
        results["vulnerabilities"].extend(ssl_vulns)
        
        # Vérifier les en-têtes de sécurité manquants
        security_header_vulns = check_security_headers(domain)
        results["vulnerabilities"].extend(security_header_vulns)
        
        # Vérifier l'âge du domaine (les domaines récents sont plus suspects)
        domain_age_vulns = check_domain_age(domain)
        if domain_age_vulns:
            results["vulnerabilities"].append(domain_age_vulns)
        
        # Vérifier les configurations DNS
        dns_vulns = check_dns_configuration(domain)
        results["vulnerabilities"].extend(dns_vulns)
        
        # Vérifier les ports ouverts
        open_ports = scan_open_ports(domain)
        results["server_info"]["ports"] = open_ports
        
        # Vérifier la présence de pages sensibles
        sensitive_pages_vulns = check_sensitive_pages(domain)
        results["vulnerabilities"].extend(sensitive_pages_vulns)
        
        # Éliminer les doublons dans les vulnérabilités
        results["vulnerabilities"] = deduplicate_vulnerabilities(results["vulnerabilities"])
        
        # Calculer le score de risque
        results["risk_score"] = calculate_risk_score(results["vulnerabilities"])
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des vulnérabilités: {e}")
        results["error"] = str(e)
    
    return results

def clean_domain(domain):
    """
    Nettoie un domaine en supprimant les protocoles et les chemins.
    
    Args:
        domain (str): Domaine à nettoyer
        
    Returns:
        str: Domaine nettoyé
    """
    # Supprimer le protocole
    domain = re.sub(r'^(https?://)?(www\.)?', '', domain)
    
    # Supprimer le chemin et les paramètres
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    
    # Supprimer le port si présent
    domain = domain.split(':')[0]
    
    return domain

def get_server_info(domain):
    """
    Récupère les informations de base du serveur.
    
    Args:
        domain (str): Domaine à analyser
        
    Returns:
        dict: Informations du serveur
    """
    server_info = {
        "server": "Inconnu",
        "technologies": [],
        "ip_addresses": [],
        "ports": [80, 443],  # Ports par défaut à vérifier
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d")
    }
    
    try:
        # Résoudre les adresses IP
        ip_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
        server_info["ip_addresses"] = list(set(ip[4][0] for ip in ip_addresses))
        
        # Essayer de récupérer les en-têtes HTTP
        response = requests.head(
            f"https://{domain}",
            headers=HEADERS,
            timeout=API_TIMEOUT,
            allow_redirects=True
        )
        
        # Extraire l'en-tête Server
        server_header = response.headers.get('Server', 'Inconnu')
        server_info["server"] = server_header
        
        # Analyser les technologies à partir des en-têtes
        server_info["technologies"] = extract_technologies_from_headers(response.headers)
        
        # Vérifier le contenu HTML pour détecter d'autres technologies
        try:
            html_response = requests.get(
                f"https://{domain}",
                headers=HEADERS,
                timeout=API_TIMEOUT
            )
            tech_from_html = extract_technologies_from_html(html_response.text)
            server_info["technologies"].extend(tech_from_html)
        except Exception as e:
            logger.warning(f"Erreur lors de l'extraction des technologies depuis HTML: {e}")
        
    except requests.exceptions.SSLError:
        # Essayer sans HTTPS
        try:
            response = requests.head(
                f"http://{domain}",
                headers=HEADERS,
                timeout=API_TIMEOUT,
                allow_redirects=True
            )
            
            server_header = response.headers.get('Server', 'Inconnu')
            server_info["server"] = server_header
            server_info["technologies"] = extract_technologies_from_headers(response.headers)
            
            # Vérifier le contenu HTML pour détecter d'autres technologies
            try:
                html_response = requests.get(
                    f"http://{domain}",
                    headers=HEADERS,
                    timeout=API_TIMEOUT
                )
                tech_from_html = extract_technologies_from_html(html_response.text)
                server_info["technologies"].extend(tech_from_html)
            except Exception as e:
                logger.warning(f"Erreur lors de l'extraction des technologies depuis HTML: {e}")
            
        except Exception as e:
            logger.warning(f"Erreur lors de la récupération des en-têtes HTTP: {e}")
    
    except Exception as e:
        logger.warning(f"Erreur lors de la récupération des informations du serveur: {e}")
    
    # Enlever les doublons dans les technologies
    server_info["technologies"] = list(set(server_info["technologies"]))
    
    return server_info

def extract_technologies_from_headers(headers):
    """
    Extrait les technologies à partir des en-têtes HTTP.
    
    Args:
        headers (dict): En-têtes HTTP
        
    Returns:
        list: Technologies détectées
    """
    technologies = []
    
    # Vérifier l'en-tête Server
    server = headers.get('Server', '')
    if server:
        # Extraire le serveur web
        if 'apache' in server.lower():
            technologies.append(f"Apache {extract_version(server)}")
        elif 'nginx' in server.lower():
            technologies.append(f"Nginx {extract_version(server)}")
        elif 'microsoft-iis' in server.lower():
            technologies.append(f"IIS {extract_version(server)}")
        elif 'lighttpd' in server.lower():
            technologies.append(f"Lighttpd {extract_version(server)}")
    
    # Vérifier l'en-tête X-Powered-By
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        if 'php' in powered_by.lower():
            technologies.append(f"PHP {extract_version(powered_by)}")
        elif 'asp.net' in powered_by.lower():
            technologies.append(f"ASP.NET {extract_version(powered_by)}")
        elif 'express' in powered_by.lower():
            technologies.append(f"Express.js {extract_version(powered_by)}")
    
    # Vérifier d'autres en-têtes
    if 'X-Drupal-Cache' in headers:
        technologies.append("Drupal")
    
    if 'X-Varnish' in headers:
        technologies.append("Varnish Cache")
    
    if 'X-Generator' in headers:
        generator = headers.get('X-Generator')
        if 'wordpress' in generator.lower():
            technologies.append(f"WordPress {extract_version(generator)}")
        elif 'joomla' in generator.lower():
            technologies.append(f"Joomla {extract_version(generator)}")
    
    # Détecter le CDN à partir des en-têtes
    if any(cdn in str(headers) for cdn in ['cloudflare', 'fastly', 'akamai', 'cloudfront']):
        if 'cloudflare' in str(headers).lower():
            technologies.append("Cloudflare CDN")
        elif 'fastly' in str(headers).lower():
            technologies.append("Fastly CDN")
        elif 'akamai' in str(headers).lower():
            technologies.append("Akamai CDN")
        elif 'cloudfront' in str(headers).lower():
            technologies.append("AWS CloudFront")
    
    return technologies

def extract_technologies_from_html(html_content):
    """
    Extrait les technologies à partir du contenu HTML.
    
    Args:
        html_content (str): Contenu HTML
        
    Returns:
        list: Technologies détectées
    """
    technologies = []
    
    # CMS populaires
    cms_patterns = {
        "WordPress": [
            r'wp-content',
            r'wp-includes',
            r'wp-json',
            r'<meta name="generator" content="WordPress'
        ],
        "Joomla": [
            r'<meta name="generator" content="Joomla',
            r'/templates/joomla',
            r'/media/jui/'
        ],
        "Drupal": [
            r'<meta name="Generator" content="Drupal',
            r'drupal.js',
            r'drupal.min.js',
            r'/sites/default/files/'
        ],
        "Magento": [
            r'<script [^>]*?Magento',
            r'var BLANK_URL = \'.*mage',
            r'magento.com/js'
        ],
        "Shopify": [
            r'cdn.shopify.com',
            r'shopify.com/s/',
            r'Shopify.theme'
        ],
        "PrestaShop": [
            r'PrestaShop',
            r'/themes/[^/]+/assets/',
            r'var prestashop ='
        ]
    }
    
    # Frameworks JavaScript
    js_frameworks = {
        "jQuery": [r'jquery', r'jQuery'],
        "React": [r'react.js', r'react-dom', r'reactjs'],
        "Vue.js": [r'vue.js', r'vue.min.js', r'vuejs'],
        "Angular": [r'angular.js', r'angular.min.js', r'ng-app'],
        "Bootstrap": [r'bootstrap.css', r'bootstrap.min.css', r'class="container'],
        "Tailwind": [r'tailwind.css', r'tailwindcss'],
        "Lodash": [r'lodash.js', r'lodash.min.js', r'_.template'],
        "Moment.js": [r'moment.js', r'moment.min.js'],
    }
    
    # Vérifier les CMS
    for cms, patterns in cms_patterns.items():
        if any(re.search(pattern, html_content) for pattern in patterns):
            # Essayer d'extraire la version
            version_match = re.search(r'{} ([0-9\.]+)'.format(cms), html_content)
            if version_match:
                technologies.append(f"{cms} {version_match.group(1)}")
            else:
                technologies.append(cms)
    
    # Vérifier les frameworks JS
    for framework, patterns in js_frameworks.items():
        if any(re.search(pattern, html_content) for pattern in patterns):
            technologies.append(framework)
    
    # Serveurs d'analyse et de marketing
    analytics_patterns = {
        "Google Analytics": [r'google-analytics.com', r'gtag', r'ga\('],
        "Google Tag Manager": [r'googletagmanager.com', r'gtm.js'],
        "Facebook Pixel": [r'connect.facebook.net', r'fbq\('],
        "Matomo": [r'matomo.js', r'piwik.js'],
        "Hotjar": [r'hotjar.com', r'hjSiteSettings']
    }
    
    for tool, patterns in analytics_patterns.items():
        if any(re.search(pattern, html_content) for pattern in patterns):
            technologies.append(tool)
    
    return technologies

def extract_version(header_value):
    """
    Extrait la version à partir d'une valeur d'en-tête.
    
    Args:
        header_value (str): Valeur de l'en-tête
        
    Returns:
        str: Version extraite ou chaîne vide
    """
    # Rechercher un motif de version (X.Y.Z)
    version_match = re.search(r'(\d+\.[\d\.]+)', header_value)
    if version_match:
        return version_match.group(1)
    return ""

def check_common_vulnerabilities(server_info):
    """
    Vérifie les vulnérabilités courantes basées sur les informations du serveur.
    
    Args:
        server_info (dict): Informations du serveur
        
    Returns:
        list: Vulnérabilités détectées
    """
    vulnerabilities = []
    
    # Combiner toutes les informations du serveur en une seule chaîne pour la vérification
    server_banner = (
        server_info.get("server", "") + " " +
        " ".join(server_info.get("technologies", []))
    ).lower()
    
    # Vérifier chaque vulnérabilité courante
    for vuln_id, vuln_info in COMMON_VULNERABILITIES.items():
        check_func = vuln_info.get("check")
        
        if check_func and check_func(server_banner):
            vuln = {
                "type": vuln_info.get("name", "Vulnérabilité inconnue"),
                "severity": vuln_info.get("severity", "Moyenne"),
                "description": vuln_info.get("description", ""),
                "recommendation": vuln_info.get("recommendation", "")
            }
            
            # Ajouter le CVE si disponible
            if "cve" in vuln_info:
                vuln["cve"] = vuln_info["cve"]
            
            vulnerabilities.append(vuln)
    
    # Vérifier les CMS populaires et leurs vulnérabilités connues
    for tech in server_info.get("technologies", []):
        tech_lower = tech.lower()
        
        # WordPress ancien
        if "wordpress" in tech_lower:
            version = extract_version(tech)
            if version and compare_versions(version, "5.8.0") < 0:
                vulnerabilities.append({
                    "type": "WordPress obsolète",
                    "severity": "Moyenne",
                    "description": f"Version {version} de WordPress obsolète qui peut contenir des vulnérabilités connues.",
                    "recommendation": "Mettre à jour WordPress vers la dernière version stable."
                })
        
        # Joomla ancien
        elif "joomla" in tech_lower:
            version = extract_version(tech)
            if version and compare_versions(version, "3.10.0") < 0:
                vulnerabilities.append({
                    "type": "Joomla obsolète",
                    "severity": "Moyenne",
                    "description": f"Version {version} de Joomla obsolète qui peut contenir des vulnérabilités connues.",
                    "recommendation": "Mettre à jour Joomla vers la dernière version stable."
                })
        
        # Drupal ancien
        elif "drupal" in tech_lower:
            version = extract_version(tech)
            if version and compare_versions(version, "9.0.0") < 0:
                vulnerabilities.append({
                    "type": "Drupal obsolète",
                    "severity": "Moyenne",
                    "description": f"Version {version} de Drupal obsolète qui peut contenir des vulnérabilités connues.",
                    "recommendation": "Mettre à jour Drupal vers la dernière version stable."
                })
    
    return vulnerabilities

def compare_versions(version1, version2):
    """
    Compare deux versions sémantiques.
    
    Args:
        version1 (str): Première version
        version2 (str): Deuxième version
        
    Returns:
        int: -1 si version1 < version2, 0 si égales, 1 si version1 > version2
    """
    v1_parts = list(map(int, re.sub(r'[^\d.]', '', version1).split('.')))
    v2_parts = list(map(int, re.sub(r'[^\d.]', '', version2).split('.')))
    
    # Ajouter des zéros si les versions n'ont pas le même nombre de parties
    while len(v1_parts) < len(v2_parts):
        v1_parts.append(0)
    while len(v2_parts) < len(v1_parts):
        v2_parts.append(0)
    
    # Comparer chaque partie
    for i in range(len(v1_parts)):
        if v1_parts[i] < v2_parts[i]:
            return -1
        elif v1_parts[i] > v2_parts[i]:
            return 1
    
    return 0

def check_ssl_vulnerabilities(domain):
    """
    Vérifie les vulnérabilités SSL/TLS d'un domaine.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        list: Vulnérabilités SSL/TLS détectées
    """
    vulnerabilities = []
    
    try:
        # Créer un contexte SSL
        context = ssl.create_default_context()
        
        # Se connecter au serveur
        with socket.create_connection((domain, 443), timeout=API_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Obtenir le certificat et la version de protocole
                cert = ssock.getpeercert()
                protocol_version = ssock.version()
                
                # Vérifier la version du protocole
                if protocol_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    vulnerabilities.append({
                        "type": "Protocole SSL/TLS obsolète",
                        "severity": "Élevée" if protocol_version in ["SSLv2", "SSLv3"] else "Moyenne",
                        "description": f"Le serveur utilise {protocol_version}, qui est considéré comme obsolète et vulnérable.",
                        "recommendation": "Configurer le serveur pour n'accepter que TLS 1.2 ou supérieur."
                    })
                
                # Vérifier la date d'expiration du certificat
                if "notAfter" in cert:
                    expiry_date = ssl.cert_time_to_seconds(cert["notAfter"])
                    current_time = time.time()
                    days_to_expire = (expiry_date - current_time) / (60 * 60 * 24)
                    
                    if days_to_expire <= 0:
                        vulnerabilities.append({
                            "type": "Certificat SSL expiré",
                            "severity": "Élevée",
                            "description": "Le certificat SSL du serveur a expiré.",
                            "recommendation": "Renouveler le certificat SSL immédiatement."
                        })
                    elif days_to_expire <= 30:
                        vulnerabilities.append({
                            "type": "Certificat SSL proche de l'expiration",
                            "severity": "Moyenne",
                            "description": f"Le certificat SSL du serveur expire dans {int(days_to_expire)} jours.",
                            "recommendation": "Planifier le renouvellement du certificat SSL."
                        })
                
                # Vérifier l'algorithme de signature
                if cert.get("signatureAlgorithm", "").startswith("sha1"):
                    vulnerabilities.append({
                        "type": "Algorithme de signature faible",
                        "severity": "Moyenne",
                        "description": "Le certificat utilise l'algorithme de signature SHA-1, qui est considéré comme faible.",
                        "recommendation": "Utiliser un certificat avec une signature SHA-256 ou supérieure."
                    })
                
                # Vérifier la présence de Subject Alternative Name
                if "subjectAltName" not in cert:
                    vulnerabilities.append({
                        "type": "SAN manquant",
                        "severity": "Faible",
                        "description": "Le certificat ne contient pas de Subject Alternative Name (SAN).",
                        "recommendation": "Utiliser un certificat avec des SAN pour une meilleure compatibilité avec les navigateurs modernes."
                    })
    
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        # Le domaine ne supporte pas HTTPS
        vulnerabilities.append({
            "type": "HTTPS non supporté",
            "severity": "Élevée",
            "description": "Le domaine ne supporte pas HTTPS, ce qui pose des risques pour la confidentialité et l'intégrité des données.",
            "recommendation": "Configurer HTTPS avec un certificat SSL valide."
        })
    except ssl.SSLError as e:
        # Erreur SSL (certificat invalide, etc.)
        vulnerabilities.append({
            "type": "Configuration SSL invalide",
            "severity": "Élevée",
            "description": f"Le serveur présente une configuration SSL invalide: {str(e)}",
            "recommendation": "Vérifier et corriger la configuration SSL du serveur."
        })
    except Exception as e:
        logger.error(f"Erreur lors de la vérification SSL: {e}")
    
    return vulnerabilities

def check_security_headers(domain):
    """
    Vérifie les en-têtes de sécurité manquants.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        list: Vulnérabilités liées aux en-têtes de sécurité manquants
    """
    vulnerabilities = []
    
    try:
        # Essayer HTTPS d'abord
        try:
            response = requests.head(
                f"https://{domain}",
                headers=HEADERS,
                timeout=API_TIMEOUT,
                allow_redirects=True
            )
        except:
            # Si HTTPS échoue, essayer HTTP
            response = requests.head(
                f"http://{domain}",
                headers=HEADERS,
                timeout=API_TIMEOUT,
                allow_redirects=True
            )
        
        # Vérifier chaque en-tête de sécurité
        for header, info in SECURITY_HEADERS.items():
            if header not in response.headers:
                vulnerabilities.append({
                    "type": f"En-tête de sécurité {header} manquant",
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des en-têtes de sécurité: {e}")
    
    return vulnerabilities

def check_domain_age(domain):
    """
    Vérifie l'âge du domaine et retourne une vulnérabilité si le domaine est récent.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        dict or None: Vulnérabilité si le domaine est récent, None sinon
    """
    try:
        if whois.is_domain_recently_created(domain, 90):
            return {
                "type": "Domaine récemment créé",
                "severity": "Faible",
                "description": "Le domaine a été créé récemment (moins de 90 jours), ce qui peut être un indicateur de phishing ou d'activité malveillante.",
                "recommendation": "Vérifier la légitimité du domaine avant de partager des informations sensibles."
            }
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'âge du domaine: {e}")
    
    return None

def check_dns_configuration(domain):
    """
    Vérifie la configuration DNS du domaine.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        list: Vulnérabilités liées à la configuration DNS
    """
    vulnerabilities = []
    
    try:
        # Vérifier les enregistrements SPF
        try:
            dns.resolver.resolve(domain, 'TXT')
            has_spf = False
            
            for record in dns.resolver.resolve(domain, 'TXT'):
                if 'v=spf1' in record.to_text():
                    has_spf = True
                    break
            
            if not has_spf:
                vulnerabilities.append({
                    "type": "Enregistrement SPF manquant",
                    "severity": "Moyenne",
                    "description": "Le domaine ne possède pas d'enregistrement SPF, ce qui peut faciliter l'usurpation d'adresses e-mail.",
                    "recommendation": "Configurer un enregistrement SPF pour le domaine."
                })
        except Exception as e:
            logger.warning(f"Erreur lors de la vérification SPF: {e}")
        
        # Vérifier les enregistrements DMARC
        try:
            dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        except:
            vulnerabilities.append({
                "type": "Enregistrement DMARC manquant",
                "severity": "Moyenne",
                "description": "Le domaine ne possède pas d'enregistrement DMARC, ce qui peut faciliter l'usurpation d'adresses e-mail et le phishing.",
                "recommendation": "Configurer un enregistrement DMARC pour le domaine."
            })
        
        # Vérifier DNSSEC
        try:
            dnssec_enabled = False
            answers = dns.resolver.resolve(domain, 'NS')
            for nameserver in answers:
                ns = str(nameserver).rstrip('.')
                try:
                    dns.resolver.resolve(domain, 'DNSKEY')
                    dnssec_enabled = True
                    break
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    pass
            
            if not dnssec_enabled:
                vulnerabilities.append({
                    "type": "DNSSEC désactivé",
                    "severity": "Faible",
                    "description": "Le domaine n'utilise pas DNSSEC, qui protège contre l'empoisonnement du cache DNS.",
                    "recommendation": "Activer DNSSEC pour le domaine."
                })
        except Exception as e:
            logger.warning(f"Erreur lors de la vérification DNSSEC: {e}")
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la configuration DNS: {e}")
    
    return vulnerabilities

def scan_open_ports(domain):
    """
    Scanne les ports ouverts d'un domaine.
    
    Args:
        domain (str): Domaine à scanner
        
    Returns:
        list: Ports ouverts détectés
    """
    open_ports = []
    
    try:
        # Résoudre l'adresse IP
        ip_address = socket.gethostbyname(domain)
        
        # Scanner les ports courants
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Timeout court pour ne pas bloquer trop longtemps
                result = sock.connect_ex((ip_address, port))
                if result == 0:  # Port ouvert
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                logger.warning(f"Erreur lors du scan du port {port}: {e}")
    
    except Exception as e:
        logger.error(f"Erreur lors du scan des ports: {e}")
    
    return open_ports

def check_sensitive_pages(domain):
    """
    Vérifie la présence de pages sensibles.
    
    Args:
        domain (str): Domaine à vérifier
        
    Returns:
        list: Vulnérabilités liées aux pages sensibles
    """
    vulnerabilities = []
    
    # Liste de chemins sensibles à vérifier
    sensitive_paths = [
        "/admin",
        "/login",
        "/wp-admin",
        "/administrator",
        "/phpmyadmin",
        "/config",
        "/.git",
        "/.env",
        "/backup",
        "/test",
        "/dev",
        "/api",
        "/console",
        "/database",
        "/server-status",
        "/status",
        "/phpinfo.php",
        "/info.php"
    ]
    
    try:
        # Déterminer si HTTPS est supporté
        https_supported = True
        try:
            requests.head(f"https://{domain}", timeout=1)
        except:
            https_supported = False
        
        # Utiliser le bon protocole
        protocol = "https" if https_supported else "http"
        
        # Vérifier chaque chemin
        for path in sensitive_paths:
            try:
                url = f"{protocol}://{domain}{path}"
                response = requests.head(
                    url,
                    headers=HEADERS,
                    timeout=2,  # Timeout court pour chaque requête
                    allow_redirects=False  # Ne pas suivre les redirections
                )
                
                # Si la page existe (code 200, 401, 403)
                if response.status_code in [200, 401, 403]:
                    # Déterminer la sévérité selon le chemin
                    severity = "Élevée" if any(critical in path for critical in [".env", ".git", "phpmyadmin", "config", "backup", "phpinfo"]) else "Moyenne"
                    
                    vulnerabilities.append({
                        "type": f"Page sensible détectée: {path}",
                        "severity": severity,
                        "description": f"Une page sensible a été détectée à l'URL {url} (code {response.status_code}).",
                        "recommendation": f"Restreindre l'accès à cette page ou la supprimer si elle n'est pas nécessaire."
                    })
            except Exception as e:
                # Ignorer les erreurs, continuer avec le chemin suivant
                pass
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des pages sensibles: {e}")
    
    return vulnerabilities

def deduplicate_vulnerabilities(vulnerabilities):
    """
    Élimine les doublons dans la liste des vulnérabilités.
    
    Args:
        vulnerabilities (list): Liste des vulnérabilités
        
    Returns:
        list: Liste des vulnérabilités sans doublons
    """
    unique_vulns = []
    vuln_types = set()
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "")
        if vuln_type not in vuln_types:
            vuln_types.add(vuln_type)
            unique_vulns.append(vuln)
    
    return unique_vulns

def calculate_risk_score(vulnerabilities):
    """
    Calcule un score de risque global basé sur les vulnérabilités détectées.
    
    Args:
        vulnerabilities (list): Liste des vulnérabilités
        
    Returns:
        int: Score de risque entre 0 et 10
    """
    if not vulnerabilities:
        return 0
    
    # Définir des poids pour chaque niveau de sévérité
    severity_weights = {
        "Critique": 10,
        "Élevée": 8,
        "Moyenne": 5,
        "Faible": 2,
        "Inconnue": 3
    }
    
    # Calculer le score total
    total_weight = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Inconnue")
        total_weight += severity_weights.get(severity, 3)
    
    # Normaliser le score entre 0 et 10
    # Plus il y a de vulnérabilités, plus le score est élevé, mais avec une limite
    normalized_score = min(10, total_weight / 10)
    
    return round(normalized_score)

# Ajouter une constante API_TIMEOUT si elle n'est pas définie dans config.py
if not 'API_TIMEOUT' in globals():
    API_TIMEOUT = 10