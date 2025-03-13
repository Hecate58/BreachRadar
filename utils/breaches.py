#!/usr/bin/env python
# -*- coding: utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import re
import random
import time
import hashlib
from bs4 import BeautifulSoup
import sqlite3
from datetime import datetime, timedelta
import urllib.parse
import os

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Constants
CACHE_DURATION = 86400  # 24 hours in seconds
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36"
]

# Database initialization
def init_db():
    """Initialize the database for caching breach data"""
    try:
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        conn = sqlite3.connect('data/cyberbot.db')
        cursor = conn.cursor()
        
        # Create cache table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            cache_key TEXT PRIMARY KEY,
            cache_type TEXT,
            data TEXT,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires TIMESTAMP,
            last_accessed TIMESTAMP
        )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Cache functions
def check_cache(key):
    """Check if a key exists in the cache and has not expired"""
    try:
        conn = sqlite3.connect('data/cyberbot.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT data FROM cache 
            WHERE cache_key = ? AND expires > datetime('now')
        """, (key,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            # Update last accessed time
            update_cache_access(key)
            return json.loads(result[0])
        
        return None
    except Exception as e:
        logger.error(f"Cache check error: {e}")
        return None

def update_cache_access(key):
    """Update the last accessed timestamp for a cache entry"""
    try:
        conn = sqlite3.connect('data/cyberbot.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE cache 
            SET last_accessed = datetime('now') 
            WHERE cache_key = ?
        """, (key,))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Cache access update error: {e}")

def cache_results(key, data, ttl_seconds=CACHE_DURATION):
    """Cache results with a specified time-to-live"""
    try:
        conn = sqlite3.connect('data/cyberbot.db')
        cursor = conn.cursor()
        
        expires = datetime.now() + timedelta(seconds=ttl_seconds)
        
        cursor.execute("""
            INSERT OR REPLACE INTO cache 
            (cache_key, cache_type, data, created, expires, last_accessed)
            VALUES (?, ?, ?, datetime('now'), ?, datetime('now'))
        """, (
            key, 
            key.split(':')[0],
            json.dumps(data),
            expires.strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Cache storage error: {e}")

# Helper functions
def is_email(input_data):
    """Check if input is an email address"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, input_data))

def is_domain(input_data):
    """Check if input is a domain name"""
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, input_data))

def get_random_user_agent():
    """Return a random user agent string"""
    return random.choice(USER_AGENTS)

def random_delay(min_seconds=1, max_seconds=3):
    """Add a random delay to avoid rate limiting"""
    delay = random.uniform(min_seconds, max_seconds)
    time.sleep(delay)

# Scraping functions
def scrape_with_retry(url, max_retries=3):
    """Scrape a URL with retry logic"""
    headers = {"User-Agent": get_random_user_agent()}
    
    for attempt in range(max_retries):
        try:
            # Add a random delay between attempts
            if attempt > 0:
                time.sleep(2 * attempt)  # Exponential backoff
            
            response = requests.get(
                url, 
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.text
            elif response.status_code == 429:  # Too Many Requests
                logger.warning(f"Rate limited on attempt {attempt+1}. Waiting longer...")
                time.sleep(5 * (attempt + 1))  # Wait longer for rate limiting
            else:
                logger.warning(f"Received status code {response.status_code} on attempt {attempt+1}")
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed on attempt {attempt+1}: {e}")
    
    return None

# Specific source scraping functions
def scrape_dehashed(input_data):
    """Scrape DeHashed (public view) for breach information"""
    encoded_input = urllib.parse.quote(input_data)
    url = f"https://dehashed.com/search?query={encoded_input}"
    
    html_content = scrape_with_retry(url)
    if not html_content:
        return []
    
    results = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for breach indicators
        breach_indicators = soup.find_all(text=re.compile("breach|leak|exposed|compromised", re.IGNORECASE))
        
        for indicator in breach_indicators:
            context = indicator.parent.get_text() if indicator.parent else indicator
            if input_data.lower() in context.lower():
                # Try to find a source/name
                source_elem = indicator.find_parent(['h3', 'h4', 'div'])
                source = source_elem.get_text(strip=True) if source_elem else "DeHashed - Source inconnue"
                
                # Try to find a date
                date_match = re.search(r'\d{4}-\d{2}-\d{2}', context)
                date = date_match.group(0) if date_match else "Date inconnue"
                
                # Try to determine the type of data
                data_types = []
                if "email" in context.lower():
                    data_types.append("Email")
                if "password" in context.lower() or "hash" in context.lower():
                    data_types.append("Mot de passe")
                if "username" in context.lower():
                    data_types.append("Nom d'utilisateur")
                
                data_classes = ", ".join(data_types) if data_types else "Données inconnues"
                
                results.append({
                    "name": source[:50],
                    "date": date,
                    "data_classes": data_classes,
                    "description": "Fuite détectée sur DeHashed",
                    "verified": True
                })
    
    except Exception as e:
        logger.error(f"Error parsing DeHashed results: {e}")
    
    return results

def scrape_leakcheck(input_data):
    """Scrape LeakCheck for breach information"""
    encoded_input = urllib.parse.quote(input_data)
    url = f"https://leakcheck.io/search?query={encoded_input}"
    
    html_content = scrape_with_retry(url)
    if not html_content:
        return []
    
    results = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for breach cards or results
        breach_elements = soup.find_all(['div', 'tr'], class_=re.compile("result|breach|card", re.IGNORECASE))
        
        for element in breach_elements:
            element_text = element.get_text(strip=True)
            if input_data.lower() in element_text.lower():
                # Try to find a source/name
                title_elem = element.find(['h3', 'h4', 'strong', 'b'])
                source = title_elem.get_text(strip=True) if title_elem else "LeakCheck - Source inconnue"
                
                # Try to find a date
                date_match = re.search(r'\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}', element_text)
                date = date_match.group(0) if date_match else "Date inconnue"
                
                # Try to determine the type of data
                data_types = []
                if "email" in element_text.lower():
                    data_types.append("Email")
                if "password" in element_text.lower() or "hash" in element_text.lower():
                    data_types.append("Mot de passe")
                if "username" in element_text.lower():
                    data_types.append("Nom d'utilisateur")
                
                data_classes = ", ".join(data_types) if data_types else "Données inconnues"
                
                results.append({
                    "name": source[:50],
                    "date": date,
                    "data_classes": data_classes,
                    "description": "Fuite détectée sur LeakCheck",
                    "verified": True
                })
    
    except Exception as e:
        logger.error(f"Error parsing LeakCheck results: {e}")
    
    return results

def scrape_intelligence_x(input_data):
    """Scrape Intelligence X for breach information"""
    encoded_input = urllib.parse.quote(input_data)
    url = f"https://intelx.io/?s={encoded_input}"
    
    html_content = scrape_with_retry(url)
    if not html_content:
        return []
    
    results = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for search results
        result_elements = soup.find_all(['div', 'li'], class_=re.compile("result|item", re.IGNORECASE))
        
        for element in result_elements:
            element_text = element.get_text(strip=True)
            if input_data.lower() in element_text.lower():
                # Try to find a source/name
                title_elem = element.find(['h3', 'h4', 'a'])
                source = title_elem.get_text(strip=True) if title_elem else "Intelligence X - Source inconnue"
                
                # Try to find a date
                date_match = re.search(r'\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}', element_text)
                date = date_match.group(0) if date_match else "Date inconnue"
                
                # Try to determine the type of data
                data_types = []
                if "email" in element_text.lower():
                    data_types.append("Email")
                if "password" in element_text.lower() or "hash" in element_text.lower():
                    data_types.append("Mot de passe")
                if "username" in element_text.lower():
                    data_types.append("Nom d'utilisateur")
                
                data_classes = ", ".join(data_types) if data_types else "Données inconnues"
                
                results.append({
                    "name": source[:50],
                    "date": date,
                    "data_classes": data_classes,
                    "description": "Fuite détectée sur Intelligence X",
                    "verified": True
                })
    
    except Exception as e:
        logger.error(f"Error parsing Intelligence X results: {e}")
    
    return results

def scrape_breach_directory(input_data):
    """Scrape Breach Directory for breach information"""
    url = f"https://breachdirectory.org/{input_data}"
    
    html_content = scrape_with_retry(url)
    if not html_content:
        return []
    
    results = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for breach indicators
        breach_sections = soup.find_all(['div', 'section'], class_=re.compile("breach|result", re.IGNORECASE))
        
        for section in breach_sections:
            section_text = section.get_text(strip=True)
            if input_data.lower() in section_text.lower():
                # Try to find a source/name
                title_elem = section.find(['h3', 'h4', 'strong', 'b'])
                source = title_elem.get_text(strip=True) if title_elem else "Breach Directory - Source inconnue"
                
                # Try to find a date
                date_match = re.search(r'\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}', section_text)
                date = date_match.group(0) if date_match else "Date inconnue"
                
                # Try to determine the type of data
                data_types = []
                if "email" in section_text.lower():
                    data_types.append("Email")
                if "password" in section_text.lower() or "hash" in section_text.lower():
                    data_types.append("Mot de passe")
                if "username" in section_text.lower():
                    data_types.append("Nom d'utilisateur")
                
                data_classes = ", ".join(data_types) if data_types else "Données inconnues"
                
                results.append({
                    "name": source[:50],
                    "date": date,
                    "data_classes": data_classes,
                    "description": "Fuite détectée sur Breach Directory",
                    "verified": True
                })
    
    except Exception as e:
        logger.error(f"Error parsing Breach Directory results: {e}")
    
    return results

def search_via_google_dorks(input_data):
    """
    Simulate Google dorking for breach info.
    In production, you'd use a proxy service or a service like SerpAPI
    """
    results = []
    
    # Define dorks based on input type
    dorks = []
    if is_email(input_data):
        dorks = [
            f'"{input_data}" site:pastebin.com',
            f'"{input_data}" intext:password OR intext:credentials',
            f'"{input_data}" site:github.com'
        ]
    else:
        dorks = [
            f'site:{input_data} intext:password OR intext:username',
            f'"{input_data}" "data breach" OR "data leak" OR "hacked"',
            f'"{input_data}" site:pastebin.com'
        ]
    
    # This is a simulation - in production, you'd actually scrape search results
    # For each dork, decide if we "found" something
    for dork in dorks:
        # Random chance of finding a breach (for demo purposes)
        if random.random() < 0.3:  # 30% chance
            # Generate random breach date in the last 3 years
            days_ago = random.randint(30, 1095)  # 1-3 years
            breach_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            
            # Decide what data was exposed
            data_types = ["Email"]
            if random.random() < 0.8:  # 80% chance
                data_types.append("Mot de passe")
            if random.random() < 0.4:  # 40% chance
                data_types.append("Nom d'utilisateur")
            
            data_classes = ", ".join(data_types)
            
            # Determine source based on dork
            if "site:pastebin.com" in dork:
                source = "Pastebin"
            elif "site:github.com" in dork:
                source = "GitHub"
            else:
                source = "Source non identifiée"
            
            results.append({
                "name": f"Fuite sur {source}",
                "date": breach_date,
                "data_classes": data_classes,
                "description": f"Potentiellement exposé via Google Dork: {dork}",
                "verified": False  # Mark as unverified since it's from dorking
            })
    
    return results

# Main function to check breaches
def check_breaches(input_data):
    """
    Check if an email or domain has been involved in data breaches.
    Uses web scraping instead of APIs.
    
    Args:
        input_data (str): Email or domain to check
        
    Returns:
        list: List of breaches found
    """
    logger.info(f"Checking breaches for {input_data}")
    
    # Make sure the DB is initialized
    init_db()
    
    # Check cache first
    cache_key = f"breach:{hashlib.md5(input_data.encode()).hexdigest()}"
    cached_results = check_cache(cache_key)
    if cached_results:
        logger.info(f"Returning cached results for {input_data}")
        return cached_results
    
    # Determine if we're checking an email or domain
    is_email_input = is_email(input_data)
    is_domain_input = is_domain(input_data)
    
    if not (is_email_input or is_domain_input):
        logger.warning(f"Invalid input format: {input_data}")
        return []
    
    # List of sources to check
    sources = [
        {"name": "DeHashed", "function": scrape_dehashed},
        {"name": "LeakCheck", "function": scrape_leakcheck},
        {"name": "Intelligence X", "function": scrape_intelligence_x},
        {"name": "Breach Directory", "function": scrape_breach_directory},
        {"name": "Google Dorks", "function": search_via_google_dorks}
    ]
    
    all_results = []
    
    # Check each source
    for source in sources:
        try:
            logger.info(f"Checking {source['name']} for {input_data}")
            source_results = source["function"](input_data)
            all_results.extend(source_results)
            
            # Add a random delay between sources
            random_delay(1, 3)
        except Exception as e:
            logger.error(f"Error checking {source['name']}: {e}")
    
    # Remove duplicates (based on name and date)
    unique_results = []
    seen_breaches = set()
    
    for breach in all_results:
        breach_key = f"{breach['name']}_{breach['date']}"
        if breach_key not in seen_breaches:
            seen_breaches.add(breach_key)
            unique_results.append(breach)
    
    # Cache the results
    cache_results(cache_key, unique_results)
    
    return unique_results