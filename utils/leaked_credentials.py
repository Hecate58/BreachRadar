#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import utils.whois as whois
import logging
import hashlib
import re
from config import API_TIMEOUT, STRONG_PASSWORD_MIN_LENGTH

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def evaluate_password_strength(password):
    """
    Évalue la force d'un mot de passe sur une échelle de 0 à 5.
    
    Args:
        password (str): Mot de passe à évaluer
        
    Returns:
        int: Score de force du mot de passe (0-5)
    """
    # Initialiser le score
    score = 0
    
    # Longueur du mot de passe
    if len(password) >= STRONG_PASSWORD_MIN_LENGTH:
        score += 1
    elif len(password) >= 8:
        score += 0.5
    
    # Présence de lettres minuscules
    if re.search(r'[a-z]', password):
        score += 1
    
    # Présence de lettres majuscules
    if re.search(r'[A-Z]', password):
        score += 1
    
    # Présence de chiffres
    if re.search(r'\d', password):
        score += 1
    
    # Présence de caractères spéciaux
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    
    # Vérifier les motifs courants qui affaiblissent un mot de passe
    if is_common_pattern(password):
        score -= 1
    
    # Limiter le score entre 0 et 5
    return max(0, min(5, score))

def is_common_pattern(password):
    """
    Vérifie si le mot de passe contient des motifs courants et faibles.
    
    Args:
        password (str): Mot de passe à vérifier
        
    Returns:
        bool: True si le mot de passe contient des motifs courants
    """
    lower_password = password.lower()
    
    # Séquences de caractères
    sequences = ['123', '234', '345', '456', '567', '678', '789', '987', '876', '765', '654', '543', '432', '321',
                'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno',
                'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz']
    
    for seq in sequences:
        if seq in lower_password:
            return True
    
    # Répétitions (ex: 'aaa', '111')
    if re.search(r'(.)\1{2,}', password):
        return True
    
    # Mots de passe courants
    common_passwords = ['password', 'qwerty', '123456', 'admin', 'welcome', 'letmein', 'monkey', 'football', 'dragon', 'baseball']
    for common in common_passwords:
        if common in lower_password:
            return True
    
    # Motifs de clavier
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'poiuyt', 'lkjhgf', 'mnbvcx']
    for pattern in keyboard_patterns:
        if pattern in lower_password:
            return True
    
    # Mots avec juste un chiffre à la fin (très courant)
    if re.match(r'^[a-zA-Z]{4,}[0-9]$', password):
        return True
    
    return False

def get_strength_label(strength):
    """
    Convertit un score de force numérique en un label descriptif.
    
    Args:
        strength (int): Score de force du mot de passe (0-5)
        
    Returns:
        str: Label descriptif
    """
    if strength >= 4.5:
        return "Très fort"
    elif strength >= 3.5:
        return "Fort"
    elif strength >= 2.5:
        return "Moyen"
    elif strength >= 1.5:
        return "Faible"
    else:
        return "Très faible"

def generate_recommendations(password, breach_count, strength):
    """
    Génère des recommandations personnalisées pour améliorer la sécurité du mot de passe.
    
    Args:
        password (str): Mot de passe évalué
        breach_count (int): Nombre de fuites dans lesquelles le mot de passe apparaît
        strength (int): Score de force du mot de passe
        
    Returns:
        list: Liste de recommandations
    """
    recommendations = []
    
    # Recommandations basées sur les fuites
    if breach_count > 0:
        recommendations.append("Changez immédiatement ce mot de passe sur tous les services où vous l'utilisez.")
        recommendations.append("Utilisez des mots de passe uniques pour chaque service.")
    
    # Recommandations basées sur la longueur
    if len(password) < STRONG_PASSWORD_MIN_LENGTH:
        recommendations.append(f"Utilisez un mot de passe d'au moins {STRONG_PASSWORD_MIN_LENGTH} caractères.")
    
    # Recommandations basées sur la diversité des caractères
    if not re.search(r'[a-z]', password):
        recommendations.append("Incluez des lettres minuscules dans votre mot de passe.")
    
    if not re.search(r'[A-Z]', password):
        recommendations.append("Incluez des lettres majuscules dans votre mot de passe.")
    
    if not re.search(r'\d', password):
        recommendations.append("Incluez des chiffres dans votre mot de passe.")
    
    if not re.search(r'[^A-Za-z0-9]', password):
        recommendations.append("Incluez des caractères spéciaux dans votre mot de passe.")
    
    # Recommandations basées sur les motifs
    if is_common_pattern(password):
        recommendations.append("Évitez les séquences et les motifs courants dans votre mot de passe.")
    
    # Recommandations générales
    recommendations.append("Envisagez d'utiliser un gestionnaire de mots de passe pour générer et stocker des mots de passe forts.")
    recommendations.append("Activez l'authentification à deux facteurs (2FA) partout où c'est possible.")
    
    return recommendations