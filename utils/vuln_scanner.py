#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import datetime
import re
import tldextract
import socket
import ssl
import fix_whois as whois


# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# API URLs
SHODAN_BASE_URL = "https://api.shodan.io"
SHODAN_HOST_URL = f"{SHODAN_BASE_URL}/shodan/host"
SHODAN_DNS_URL = f"{SHODAN_BASE_URL}/dns/resolve"

# En-têtes communs pour les requêtes
HEADERS = {
    "User-Agent": "Cybersecurity-Telegram-Bot"
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
        
        # Si nous avons une clé API Shodan, utiliser Shodan pour des informations supplémentaires
        if SHODAN_API_KEY:
            shodan_results = scan_with_shodan(domain)
            if shodan_results:
                # Mettre à jour les informations du serveur
                results["server_info"]["technologies"].extend(shodan_results.get("technologies", []))
                results["server_info"]["ports"].extend(shodan_results.get("ports", []))
                results["server_info"]["last_updated"] = shodan_results.get("last_update", results["server_info"]["last_updated"])
                
                # Ajouter les vulnérabilités trouvées par Shodan
                results["vulnerabilities"].extend(shodan_results.get("vulnerabilities", []))
        
        # Vérifier les vulnérabilités courantes basées sur les informations du serveur
        custom_vulns = check_common_vulnerabilities(results["server_info"])
        results["vulnerabilities"].extend(custom_vulns)
        
        # Vérifier les problèmes de configuration SSL/TLS
        ssl_vulns = check_ssl_vulnerabilities(domain)
        results["vulnerabilities"].extend(ssl_vulns)
        
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
            
        except Exception as e:
            logger.warning(f"Erreur lors de la récupération des en-têtes HTTP: {e}")
    
    except Exception as e:
        logger.warning(f"Erreur lors de la récupération des informations du serveur: {e}")
    
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

def scan_with_shodan(domain):
    """
    Utilise l'API Shodan pour récupérer des informations sur un domaine.
    
    Args:
        domain (str): Domaine à analyser
        
    Returns:
        dict: Résultats de la recherche Shodan
    """
    if not SHODAN_API_KEY:
        logger.warning("Clé API Shodan non configurée")
        return None
    
    results = {
        "technologies": [],
        "ports": [],
        "vulnerabilities": [],
        "last_update": "N/A"
    }
    
    try:
        # Résoudre le domaine en adresse IP via Shodan
        resolve_url = f"{SHODAN_DNS_URL}?hostnames={domain}&key={SHODAN_API_KEY}"
        resolve_response = requests.get(
            resolve_url,
            headers=HEADERS,
            timeout=API_TIMEOUT
        )
        
        if resolve_response.status_code != 200:
            logger.error(f"Erreur Shodan DNS: {resolve_response.status_code} - {resolve_response.text}")
            return None
        
        ip_data = resolve_response.json()
        ip_address = ip_data.get(domain)
        
        if not ip_address:
            logger.warning(f"Impossible de résoudre {domain} via Shodan")
            return None
        
        
        # Extraire les ports
        if "ports" in host_data:
            results["ports"] = host_data["ports"]
        
        # Extraire la date de dernière mise à jour
        if "last_update" in host_data:
            last_update = datetime.datetime.strptime(
                host_data["last_update"],
                "%Y-%m-%dT%H:%M:%S.%f"
            )
            results["last_update"] = last_update.strftime("%Y-%m-%d")
        
        # Extraire les technologies et vulnérabilités des données de service
        if "data" in host_data:
            for service in host_data["data"]:
                # Extraire les technologies
                product = service.get("product", "")
                version = service.get("version", "")
                if product:
                    tech = product
                    if version:
                        tech += f" {version}"
                    results["technologies"].append(tech)
                
                # Extraire les vulnérabilités
                if "vulns" in service:
                    for cve_id, vuln_info in service["vulns"].items():
                        # Créer une entrée de vulnérabilité
                        vuln = {
                            "type": vuln_info.get("summary", "Vulnérabilité inconnue"),
                            "severity": map_cvss_to_severity(vuln_info.get("cvss", 0)),
                            "description": vuln_info.get("summary", ""),
                            "cve": cve_id,
                            "recommendation": "Mettre à jour le logiciel vulnérable vers la dernière version."
                        }
                        results["vulnerabilities"].append(vuln)
        
    except Exception as e:
        logger.error(f"Erreur lors de la recherche Shodan: {e}")
        return None
    
    return results

def map_cvss_to_severity(cvss):
    """
    Mappe un score CVSS à un niveau de sévérité.
    
    Args:
        cvss (float): Score CVSS
        
    Returns:
        str: Niveau de sévérité
    """
    if cvss >= 9.0:
        return "Critique"
    elif cvss >= 7.0:
        return "Élevée"
    elif cvss >= 4.0:
        return "Moyenne"
    elif cvss > 0:
        return "Faible"
    else:
        return "Inconnue"

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
    
    return vulnerabilities

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