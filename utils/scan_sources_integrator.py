#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import re
import urllib.parse
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Configuration des sources
from config import (
    GITHUB_TOKEN,
    REDDIT_CLIENT_ID,
    REDDIT_CLIENT_SECRET,
    ALIENVAULT_API_KEY,
    URLSCAN_API_KEY
)

# Configuration du logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class DarkwebSourcesIntegrator:
    def __init__(self):
        """
        Initialise l'intégrateur avec les configurations des sources
        """
        self.session = requests.Session()
        self.sources = {
            'github': self._setup_github_source(),
            'reddit': self._setup_reddit_source(),
            'alienvault': self._setup_alienvault_source(),
            'urlscan': self._setup_urlscan_source(),
            'pastebin': self._setup_pastebin_source(),
            'leak_databases': self._setup_leak_databases(),
            'forums': self._setup_private_forums(),
            'google_dorks': self._setup_google_dorks()
        }

    def _setup_github_source(self):
        """
        Configuration de la source GitHub
        """
        return {
            'api_url': 'https://api.github.com/search/code',
            'headers': {
                'Authorization': f'token {GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json'
            },
            'rate_limit': {
                'limit': 10,  # requêtes par minute
                'reset_time': datetime.now()
            }
        }

    def _setup_reddit_source(self):
        """
        Configuration de la source Reddit
        """
        # Obtenir un token d'accès
        auth = requests.auth.HTTPBasicAuth(
            REDDIT_CLIENT_ID, 
            REDDIT_CLIENT_SECRET
        )
        
        data = {
            'grant_type': 'client_credentials',
            'duration': 'permanent'
        }
        
        headers = {'User-Agent': 'BreacheRadar/1.0'}
        
        try:
            response = requests.post(
                'https://www.reddit.com/api/v1/access_token', 
                auth=auth, 
                data=data, 
                headers=headers
            )
            token = response.json()['access_token']
        except Exception as e:
            logger.error(f"Erreur d'authentification Reddit : {e}")
            token = None

        return {
            'api_url': 'https://oauth.reddit.com/search',
            'headers': {
                'Authorization': f'bearer {token}',
                'User-Agent': 'BreacheRadar/1.0'
            },
            'subreddits': [
                'netsec', 'cybersecurity', 'privacy', 
                'hacking', 'leaks', 'security'
            ]
        }

    def _setup_alienvault_source(self):
        """
        Configuration de la source AlienVault OTX
        """
        return {
            'api_url': 'https://otx.alienvault.com/api/v1/indicators',
            'headers': {
                'X-OTX-API-KEY': ALIENVAULT_API_KEY,
                'User-Agent': 'BreacheRadar/1.0'
            },
            'rate_limit': {
                'limit': 750,  # requêtes par jour
                'reset_time': datetime.now() + timedelta(days=1)
            }
        }

    def _setup_urlscan_source(self):
        """
        Configuration de la source URLScan.io
        """
        return {
            'api_url': 'https://urlscan.io/api/v1/search/',
            'headers': {
                'API-Key': URLSCAN_API_KEY,
                'Content-Type': 'application/json'
            },
            'rate_limit': {
                'limit': 5000,  # scans par mois
                'reset_time': datetime.now() + timedelta(days=30)
            }
        }

    def _setup_pastebin_source(self):
        """
        Configuration de la source Pastebin
        Note: Le scraping de Pastebin est complexe et légalement risqué
        """
        return {
            'search_url': 'https://pastebin.com/search',
            'scraping_method': 'limited_public_search',
            'rate_limit': {
                'limit': 10,  # requêtes par heure
                'reset_time': datetime.now() + timedelta(hours=1)
            }
        }

    def _setup_leak_databases(self):
        """
        Configuration des bases de données de fuites
        Note: Nécessite une approche prudente et éthique
        """
        return {
            'sources': [
                'LeakBase',
                'Leak-Lookup',
                'DeHashed (version publique)'
            ],
            'method': 'aggregation_and_verification'
        }

    def _setup_private_forums(self):
        """
        Gestion des forums privés
        Note: Accès très limité et complexe
        """
        return {
            'forums': [
                'HackForums',
                'NulledBB',
                'RaidForums'
            ],
            'access_method': 'external_intelligence_gathering'
        }

    def _setup_google_dorks(self):
        """
        Configuration des Google Dorks
        Note: Scraping complexe et potentiellement contre les CGU
        """
        return {
            'search_strategies': [
                'intitle:{term}',
                'inurl:{term}',
                'site:pastebin.com "{term}"',
                'ext:txt "{term}"'
            ],
            'method': 'simulation_and_aggregation'
        }

    def search_github(self, search_term: str) -> List[Dict[str, Any]]:
        """
        Recherche de code sur GitHub
        
        :param search_term: Terme à rechercher
        :return: Liste des résultats
        """
        github_config = self.sources['github']
        
        try:
            response = self.session.get(
                github_config['api_url'],
                headers=github_config['headers'],
                params={'q': search_term, 'per_page': 10}
            )
            
            if response.status_code == 200:
                results = response.json().get('items', [])
                return [
                    {
                        'source': 'GitHub',
                        'repository': item['repository']['full_name'],
                        'filename': item['name'],
                        'url': item['html_url'],
                        'language': item.get('language', 'Unknown'),
                        'score': self._calculate_github_risk_score(item)
                    } for item in results
                ]
        except Exception as e:
            logger.error(f"Erreur recherche GitHub : {e}")
        
        return []

    def _calculate_github_risk_score(self, item: Dict[str, Any]) -> int:
        """
        Calcule un score de risque pour un résultat GitHub
        
        :param item: Résultat GitHub
        :return: Score de risque
        """
        risk_score = 0
        
        # Mots-clés sensibles
        sensitive_keywords = [
            'password', 'secret', 'credential', 'token', 
            'leak', 'vulnerability', 'exploit'
        ]
        
        # Vérifier le nom du fichier
        filename = item['name'].lower()
        risk_score += sum(10 for keyword in sensitive_keywords if keyword in filename)
        
        # Vérifier la popularité du dépôt
        stars = item['repository'].get('stargazers_count', 0)
        risk_score += min(stars // 100, 10)  # Max 10 points
        
        return min(risk_score, 50)  # Limiter à 50

    def consolidate_results(self, search_term: str) -> Dict[str, Any]:
        """
        Consolide les résultats de toutes les sources
        
        :param search_term: Terme à rechercher
        :return: Résultats consolidés
        """
        consolidated_results = {
            'search_term': search_term,
            'total_mentions': 0,
            'sources': [],
            'risk_analysis': {
                'overall_risk_score': 0,
                'risk_categories': {}
            }
        }
        
        # Sources à rechercher
        search_methods = [
            self.search_github
            # Ajouter d'autres méthodes de recherche ici
        ]
        
        # Exécuter chaque méthode de recherche
        for method in search_methods:
            try:
                results = method(search_term)
                
                # Ajouter les résultats
                consolidated_results['sources'].extend(results)
                consolidated_results['total_mentions'] += len(results)
                
                # Analyser les risques
                for result in results:
                    score = result.get('score', 0)
                    consolidated_results['risk_analysis']['overall_risk_score'] += score
            except Exception as e:
                logger.error(f"Erreur lors de la consolidation : {e}")
        
        # Calculer le score de risque moyen
        if consolidated_results['total_mentions'] > 0:
            consolidated_results['risk_analysis']['overall_risk_score'] /= consolidated_results['total_mentions']
        
        return consolidated_results

# Exemple d'utilisation
def main():
    integrator = DarkwebSourcesIntegrator()
    
    # Exemple de recherche
    search_term = "sensitive_data"
    results = integrator.consolidate_results(search_term)
    
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()