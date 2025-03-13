#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Module officiel implémentant les requêtes WHOIS pour le bot de cybersécurité.
Cette implémentation remplace la version simulée dans fix_whois.py.
"""

import whois
import logging
import datetime
import socket
import tldextract
import re
import time
from config import API_TIMEOUT

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def query(domain):
    """
    Fonction qui effectue une requête WHOIS pour le domaine spécifié.
    
    Args:
        domain (str): Nom de domaine à interroger
        
    Returns:
        WhoisEntry: Objet contenant les informations WHOIS
    """
    return whois_query(domain)

def get_whois(domain):
    """
    Alias de la fonction query pour rétrocompatibilité.
    
    Args:
        domain (str): Nom de domaine à interroger
        
    Returns:
        WhoisEntry: Objet contenant les informations WHOIS
    """
    return whois_query(domain)

def whois_query(domain):
    """
    Effectue une requête WHOIS et gère les erreurs potentielles.
    
    Args:
        domain (str): Nom de domaine à interroger
        
    Returns:
        WhoisEntry: Objet contenant les informations WHOIS
    """
    try:
        # Nettoyer le domaine d'entrée
        cleaned_domain = clean_domain(domain)
        
        # Extraire le domaine principal (sans sous-domaines)
        ext = tldextract.extract(cleaned_domain)
        base_domain = f"{ext.domain}.{ext.suffix}"
        
        # Limiter les requêtes pour éviter le rate-limiting
        time.sleep(0.5)
        
        # Effectuer la requête WHOIS
        whois_result = whois.query(base_domain)
        
        # En cas de résultat None, créer un objet WhoisResult simplifié
        if whois_result is None:
            logger.warning(f"Aucun résultat WHOIS pour {base_domain}, création d'un objet simplifié")
            return create_empty_whois_result(base_domain)
        
        return whois_result
    
    except (whois.exceptions.WhoisException, whois.exceptions.FailedParsingWhoisOutput) as e:
        logger.error(f"Erreur lors de l'analyse WHOIS pour {domain}: {e}")
        return create_empty_whois_result(domain)
    
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la requête WHOIS pour {domain}: {e}")
        return create_empty_whois_result(domain)

def clean_domain(domain):
    """
    Nettoie une URL pour extraire uniquement le nom de domaine.
    
    Args:
        domain (str): URL ou domaine à nettoyer
        
    Returns:
        str: Domaine nettoyé
    """
    # Supprimer le protocole
    domain = re.sub(r'^(https?://)?(www\.)?', '', domain)
    
    # Supprimer le chemin, les requêtes et fragments
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    
    # Supprimer le port si présent
    domain = domain.split(':')[0]
    
    return domain

def create_empty_whois_result(domain):
    """
    Crée un objet WhoisResult simplifié pour les cas où la requête échoue.
    Assure la compatibilité avec le reste du code.
    
    Args:
        domain (str): Nom de domaine
        
    Returns:
        WhoisResult: Objet simplifié avec les attributs requis
    """
    class WhoisResult:
        def __init__(self, domain):
            self.domain = domain
            self.registrar = None
            self.creation_date = None
            self.expiration_date = None
            self.updated_date = None
            self.status = None
            self.name_servers = []
            self.emails = []
            self.dnssec = None
            
            # Propriétés pour le registrant
            self.registrant_name = None
            self.registrant_organization = None
            self.registrant_country = None
            
            # Propriété supplémentaire pour indiquer un domaine inexistant
            self.domain_exists = False
    
    return WhoisResult(domain)

def get_domain_age(domain):
    """
    Calcule l'âge d'un domaine en se basant sur sa date de création.
    
    Args:
        domain (str): Nom de domaine
        
    Returns:
        str: Description textuelle de l'âge du domaine
    """
    try:
        domain_info = whois_query(domain)
        
        if domain_info and domain_info.creation_date:
            creation_date = domain_info.creation_date
            
            # Standardiser au format datetime si c'est une liste
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Calculer la différence avec aujourd'hui
            now = datetime.datetime.now()
            age_timedelta = now - creation_date
            
            # Calculer les années et mois
            years = age_timedelta.days // 365
            months = (age_timedelta.days % 365) // 30
            days = age_timedelta.days % 30
            
            # Générer une description lisible
            if years > 0:
                if months > 0:
                    return f"{years} an{'s' if years > 1 else ''} et {months} mois"
                else:
                    return f"{years} an{'s' if years > 1 else ''}"
            elif months > 0:
                return f"{months} mois"
            else:
                return f"{days} jour{'s' if days > 1 else ''}"
        else:
            return "Inconnu"
    
    except Exception as e:
        logger.error(f"Erreur lors du calcul de l'âge du domaine {domain}: {e}")
        return "Inconnu"

def is_domain_recently_created(domain, days_threshold=90):
    """
    Vérifie si un domaine a été créé récemment (ce qui peut être un indicateur de risque).
    
    Args:
        domain (str): Nom de domaine
        days_threshold (int): Seuil en jours pour considérer un domaine comme récent
        
    Returns:
        bool: True si le domaine est récent, False sinon
    """
    try:
        domain_info = whois_query(domain)
        
        if domain_info and domain_info.creation_date:
            creation_date = domain_info.creation_date
            
            # Standardiser au format datetime si c'est une liste
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Calculer l'âge en jours
            now = datetime.datetime.now()
            age_days = (now - creation_date).days
            
            return age_days < days_threshold
        
        return False
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'âge du domaine {domain}: {e}")
        return False

def get_domain_expiry_status(domain):
    """
    Vérifie le statut d'expiration du domaine.
    
    Args:
        domain (str): Nom de domaine
        
    Returns:
        dict: Statut d'expiration avec informations détaillées
    """
    try:
        domain_info = whois_query(domain)
        
        if domain_info and domain_info.expiration_date:
            expiry_date = domain_info.expiration_date
            
            # Standardiser au format datetime si c'est une liste
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            
            # Calculer les jours restants
            now = datetime.datetime.now()
            days_remaining = (expiry_date - now).days
            
            status = {
                "expiry_date": expiry_date.strftime("%Y-%m-%d"),
                "days_remaining": days_remaining,
                "is_expired": days_remaining < 0,
                "status": "Expiré" if days_remaining < 0 else (
                    "Critique" if days_remaining < 7 else (
                    "Alerte" if days_remaining < 30 else (
                    "Attention" if days_remaining < 90 else "Normal"
                ))),
                "description": get_expiry_description(days_remaining)
            }
            
            return status
        
        return {
            "expiry_date": "Inconnu",
            "days_remaining": None,
            "is_expired": None,
            "status": "Inconnu",
            "description": "Impossible de déterminer la date d'expiration du domaine."
        }
    
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'expiration du domaine {domain}: {e}")
        return {
            "expiry_date": "Erreur",
            "days_remaining": None,
            "is_expired": None,
            "status": "Erreur",
            "description": f"Erreur lors de la vérification: {str(e)}"
        }

def get_expiry_description(days_remaining):
    """
    Génère une description textuelle basée sur les jours restants avant expiration.
    
    Args:
        days_remaining (int): Nombre de jours avant expiration
        
    Returns:
        str: Description textuelle
    """
    if days_remaining < 0:
        return f"Le domaine a expiré il y a {abs(days_remaining)} jour{'s' if abs(days_remaining) > 1 else ''}."
    elif days_remaining < 7:
        return f"URGENT: Le domaine expire dans {days_remaining} jour{'s' if days_remaining > 1 else ''}!"
    elif days_remaining < 30:
        return f"Alerte: Le domaine expire dans {days_remaining} jours (moins d'un mois)."
    elif days_remaining < 90:
        return f"Attention: Le domaine expire dans {days_remaining} jours (moins de trois mois)."
    else:
        return f"Le domaine expire dans {days_remaining} jours."