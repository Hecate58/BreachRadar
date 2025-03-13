#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import re
import random
import time
import hashlib
import urllib.parse
import socket
import ssl
import sqlite3
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import os
import tldextract
import ipaddress

# Configuration du système de journalisation
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Constants
CACHE_DURATION = 43200  # 12 hours in seconds
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36"
]

# Lists of suspicious indicators
PHISHING_KEYWORDS = [
    'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 
    'banking', 'confirm', 'update', 'verify', 'login', 'paypal',
    'password', 'credential', 'wallet', 'verification', 'authenticate',
    'recovery', 'authorize', 'validation'
]

SUSPICIOUS_TLD = [
    'tk', 'ga', 'ml', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date', 
    'wang', 'party', 'gdn', 'stream', 'bid', 'click', 'surf', 'trade', 
    'review', 'racing'
]

POPULAR_BRANDS = [
    'google', 'facebook', 'apple', 'amazon', 'microsoft', 'paypal', 'netflix',
    'linkedin', 'twitter', 'instagram', 'bank', 'wellsfargo', 'bankofamerica',
    'chase', 'amex', 'american express', 'visa', 'mastercard', 'gmail', 'yahoo',
    'outlook', 'hotmail', 'office365', 'dropbox', 'steam', 'discord', 'zoom'
]

# Initialize database
def init_db():
    """Initialize the database for caching URL analysis results"""
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
def get_random_user_agent():
    """Return a random user agent string"""
    return random.choice(USER_AGENTS)

def normalize_url(url):
    """Normalize URL for consistent analysis"""
    # Ensure URL starts with protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse and normalize
    parsed = urllib.parse.urlparse(url)
    
    # Normalize hostname to lowercase
    netloc = parsed.netloc.lower()
    
    # Normalize path, removing trailing slash if it's the only path component
    path = parsed.path
    if path == '/':
        path = ''
    
    # Reconstruct the URL
    normalized = urllib.parse.urlunparse((
        parsed.scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
    return normalized

def is_ip_address(hostname):
    """Check if hostname is an IP address"""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def follow_redirects(url, max_redirects=10):
    """Follow URL redirects and return the chain"""
    headers = {"User-Agent": get_random_user_agent()}
    redirect_chain = []
    current_url = url
    
    try:
        for i in range(max_redirects):
            response = requests.head(
                current_url, 
                headers=headers,
                allow_redirects=False,
                timeout=10
            )
            
            redirect_chain.append({
                "url": current_url,
                "status_code": response.status_code
            })
            
            # Check if it's a redirect
            if response.status_code in (301, 302, 303, 307, 308):
                if 'Location' in response.headers:
                    # Get the redirect location
                    next_url = response.headers['Location']
                    
                    # Handle relative URLs
                    if next_url.startswith('/'):
                        parsed_current = urllib.parse.urlparse(current_url)
                        next_url = f"{parsed_current.scheme}://{parsed_current.netloc}{next_url}"
                    
                    current_url = next_url
                else:
                    break
            else:
                break
    except Exception as e:
        logger.error(f"Error following redirects for {url}: {e}")
        redirect_chain.append({
            "url": current_url,
            "status_code": -1,
            "error": str(e)
        })
    
    return redirect_chain

def check_ssl_certificate(hostname):
    """Verify SSL certificate and return details"""
    result = {
        "valid": False,
        "version": None,
        "issuer": None,
        "expiry": None,
        "issues": []
    }
    
    # Skip check if it's an IP address
    if is_ip_address(hostname):
        result["issues"].append("URL uses IP address instead of domain name")
        return result
    
    # Try to extract the domain without port
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate details
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                result["valid"] = True
                result["version"] = version
                
                # Get issuer
                issuer_components = dict(x[0] for x in cert['issuer'])
                result["issuer"] = issuer_components.get('organizationName', 'Unknown')
                
                # Check expiry
                not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                current_time = time.time()
                days_remaining = int((not_after - current_time) / (60*60*24))
                
                result["expiry"] = {
                    "date": cert['notAfter'],
                    "days_remaining": days_remaining
                }
                
                # Check for weak protocols
                if version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                    result["issues"].append(f"Uses outdated {version} protocol")
                
                # Check for expiring certificate
                if days_remaining <= 0:
                    result["issues"].append("Certificate has expired")
                elif days_remaining <= 14:
                    result["issues"].append(f"Certificate expires in {days_remaining} days")
    
    except ssl.SSLError as e:
        result["issues"].append(f"SSL Error: {str(e)}")
    except (socket.timeout, socket.error, ConnectionRefusedError) as e:
        result["issues"].append(f"Connection error: {str(e)}")
    except Exception as e:
        result["issues"].append(f"Error checking SSL: {str(e)}")
    
    return result

def analyze_url_structure(url):
    """Analyze URL structure for suspicious patterns"""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    fragment = parsed.fragment.lower()
    
    # Extract domain information
    extracted = tldextract.extract(hostname)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    
    issues = []
    score = 100  # Start with perfect score and deduct for issues
    
    # Check for IP address instead of domain name
    if is_ip_address(hostname.split(':')[0]):
        issues.append("URL uses an IP address instead of a domain name")
        score -= 30
    
    # Check for suspicious TLDs
    if suffix in SUSPICIOUS_TLD:
        issues.append(f"URL uses suspicious TLD (.{suffix})")
        score -= 15
    
    # Check for phishing keywords in different parts
    phishing_keywords_found = []
    
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain or keyword in subdomain:
            phishing_keywords_found.append(keyword)
        elif keyword in path:
            phishing_keywords_found.append(keyword)
    
    if phishing_keywords_found:
        issues.append(f"URL contains phishing keywords: {', '.join(phishing_keywords_found)}")
        score -= len(phishing_keywords_found) * 5
    
    # Check for spoofing of popular brands
    for brand in POPULAR_BRANDS:
        if brand in domain or brand in subdomain:
            # Check if it's not actually the official domain
            if not is_official_domain(hostname, brand):
                issues.append(f"URL may be spoofing the {brand} brand")
                score -= 25
                break
    
    # Check for excessive subdomains (potential for confusion)
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    if subdomain_count > 3:
        issues.append(f"URL has an unusually high number of subdomains ({subdomain_count})")
        score -= 10
    
    # Check for very long hostnames (potential for obfuscation)
    if len(hostname) > 40:
        issues.append("URL has an unusually long hostname")
        score -= 15
    
    # Check for suspicious characters in URL
    if re.search(r'%[0-9A-Fa-f]{2}', url):
        issues.append("URL contains percent-encoded characters")
        score -= 10
    
    # Check for suspicious query parameters
    suspicious_params = ['password', 'passwd', 'pwd', 'userpass', 'login', 'token', 'verify']
    for param in suspicious_params:
        if f"{param}=" in query:
            issues.append(f"URL contains sensitive parameter: {param}")
            score -= 15
            break
    
    # Check for data URLs
    if url.startswith("data:"):
        issues.append("URL uses data: scheme which can hide malicious content")
        score -= 50
    
    # Check for Unicode characters (potential for homograph attacks)
    if any(ord(c) > 127 for c in hostname):
        issues.append("URL contains Unicode characters (potential homograph attack)")
        score -= 25
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    return {
        "score": score,
        "issues": issues,
        "hostname": hostname,
        "domain": domain,
        "tld": suffix,
        "subdomains": subdomain
    }

def is_official_domain(hostname, brand):
    """Check if the hostname is an official domain for the brand"""
    # Map of brands to their official domains
    official_domains = {
        'google': ['google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'ytimg.com'],
        'facebook': ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com'],
        'apple': ['apple.com', 'icloud.com', 'mzstatic.com', 'itunes.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazonaws.com'],
        'microsoft': ['microsoft.com', 'msn.com', 'live.com', 'outlook.com', 'office365.com', 'azure.com'],
        'paypal': ['paypal.com', 'paypal.me'],
        'netflix': ['netflix.com', 'nflximg.net', 'nflxvideo.net'],
        'linkedin': ['linkedin.com', 'licdn.com'],
        'twitter': ['twitter.com', 'twimg.com', 't.co', 'x.com'],
        'instagram': ['instagram.com', 'cdninstagram.com'],
        'yahoo': ['yahoo.com', 'yimg.com'],
        'gmail': ['gmail.com', 'mail.google.com'],
        'outlook': ['outlook.com', 'outlook.live.com', 'hotmail.com']
    }
    
    # Extract the base domain
    extracted = tldextract.extract(hostname)
    base_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Check if it's in the list of official domains
    if brand in official_domains:
        for domain in official_domains[brand]:
            if base_domain == domain or hostname.endswith(f".{domain}"):
                return True
    
    # For brands not in our map, a simple check
    return base_domain == f"{brand}.com"

def analyze_page_content(url):
    """Analyze page content for phishing indicators"""
    headers = {"User-Agent": get_random_user_agent()}
    result = {
        "analyzed": False,
        "title": None,
        "forms": False,
        "password_fields": False,
        "login_terms": False,
        "external_resources": 0,
        "iframe_count": 0,
        "script_count": 0,
        "issues": []
    }
    
    try:
        # Request with timeout to avoid hanging
        response = requests.get(url, headers=headers, timeout=15)
        
        # Check if it's HTML content
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type:
            result["issues"].append(f"Not HTML content (Content-Type: {content_type})")
            return result
        
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Set analyzed flag
        result["analyzed"] = True
        
        # Extract page title
        title_tag = soup.find('title')
        result["title"] = title_tag.text if title_tag else "No title"
        
        # Look for forms
        forms = soup.find_all('form')
        result["forms"] = len(forms) > 0
        
        # Check for password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        result["password_fields"] = len(password_fields) > 0
        
        # Look for login terms in page text
        page_text = soup.get_text().lower()
        login_terms = ['login', 'sign in', 'signin', 'log in', 'username', 'password', 'user id', 'account']
        result["login_terms"] = any(term in page_text for term in login_terms)
        
        # Count external resources
        base_domain = tldextract.extract(url).registered_domain
        
        external_resources = 0
        for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
            src = tag.get('src') or tag.get('href')
            if src and not src.startswith(('data:', '#', '/')):
                try:
                    res_domain = tldextract.extract(src).registered_domain
                    if res_domain and res_domain != base_domain:
                        external_resources += 1
                except:
                    pass
        
        result["external_resources"] = external_resources
        
        # Count iframes
        result["iframe_count"] = len(soup.find_all('iframe'))
        
        # Count scripts
        result["script_count"] = len(soup.find_all('script'))
        
        # Check for suspicious content patterns
        # 1. Forms that submit to external domains
        for form in forms:
            action = form.get('action', '')
            if action and not action.startswith(('/', '#')):
                try:
                    form_domain = tldextract.extract(action).registered_domain
                    if form_domain != base_domain:
                        result["issues"].append(f"Form submits to external domain: {form_domain}")
                except:
                    pass
        
        # 2. Password field in a non-HTTPS page
        if result["password_fields"] and not url.startswith('https://'):
            result["issues"].append("Password field on a non-HTTPS page")
        
        # 3. Hidden fields with suspicious names
        hidden_fields = soup.find_all('input', {'type': 'hidden'})
        for field in hidden_fields:
            name = field.get('name', '').lower()
            if any(term in name for term in ['token', 'auth', 'redirect', 'return', 'next']):
                result["issues"].append(f"Suspicious hidden field: {name}")
        
        # 4. Excessive number of iframes
        if result["iframe_count"] > 3:
            result["issues"].append(f"Excessive number of iframes: {result['iframe_count']}")
        
        # 5. Check for brand names in title
        for brand in POPULAR_BRANDS:
            if brand.lower() in result["title"].lower():
                # Check if the URL is from the official domain
                if not is_official_domain(urllib.parse.urlparse(url).netloc, brand):
                    result["issues"].append(f"Page title contains '{brand}' but URL is not an official {brand} domain")
    
    except Exception as e:
        result["issues"].append(f"Error analyzing page content: {str(e)}")
    
    return result

def check_domain_reputation(domain):
    """Check domain reputation via scraping public blocklists"""
    reputation = {
        "score": 70,  # Default neutral score
        "blacklisted": False,
        "lists": [],
        "age_days": None,
        "issues": []
    }
    
    try:
        # Try to get domain age (approximation)
        try:
            response = requests.get(f"https://whois.domaintools.com/{domain}", 
                                  headers={"User-Agent": get_random_user_agent()},
                                  timeout=10)
            
            if response.status_code == 200:
                # Look for creation date pattern
                date_match = re.search(r'Created on ([A-Za-z]+ \d{1,2}, \d{4})', response.text)
                if date_match:
                    creation_date_str = date_match.group(1)
                    try:
                        creation_date = datetime.strptime(creation_date_str, "%B %d, %Y")
                        reputation["age_days"] = (datetime.now() - creation_date).days
                        
                        # Adjust score based on age
                        if reputation["age_days"] < 30:
                            reputation["score"] -= 20
                            reputation["issues"].append("Domain is less than 30 days old")
                        elif reputation["age_days"] < 90:
                            reputation["score"] -= 10
                            reputation["issues"].append("Domain is less than 90 days old")
                    except:
                        pass
        except:
            pass
        
        # Check common blacklists by scraping an aggregator
        try:
            response = requests.get(f"https://check.spamhaus.org/domain/{domain}/",
                                  headers={"User-Agent": get_random_user_agent()},
                                  timeout=10)
            
            if response.status_code == 200 and "is currently listed" in response.text:
                reputation["blacklisted"] = True
                reputation["lists"].append("Spamhaus")
                reputation["score"] -= 30
                reputation["issues"].append("Listed on Spamhaus blocklist")
        except:
            pass
        
        # Additional check via urlvoid-like service
        try:
            response = requests.get(f"https://urlvoid.com/scan/{domain}/",
                                   headers={"User-Agent": get_random_user_agent()},
                                   timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for detection results
                detection_elements = soup.find_all(text=re.compile("Detections:"))
                for elem in detection_elements:
                    if "Detections:" in elem:
                        count_match = re.search(r'Detections: (\d+)/\d+', elem)
                        if count_match and int(count_match.group(1)) > 0:
                            reputation["blacklisted"] = True
                            reputation["lists"].append("URLVoid Aggregate")
                            reputation["score"] -= int(count_match.group(1)) * 5
                            reputation["issues"].append(f"Listed on {count_match.group(1)} security blocklists according to URLVoid")
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error checking domain reputation for {domain}: {e}")
    
    # Ensure score stays within bounds
    reputation["score"] = max(0, min(100, reputation["score"]))
    
    return reputation

def analyze_url(url):
    """
    Main function to analyze URL security.
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Analysis results with security score and issues
    """
    logger.info(f"Analyzing URL: {url}")
    
    # Make sure DB is initialized
    init_db()
    
    # Normalize the URL for consistent analysis
    normalized_url = normalize_url(url)
    
    # Check cache first
    cache_key = f"url:{hashlib.md5(normalized_url.encode()).hexdigest()}"
    cached_results = check_cache(cache_key)
    if cached_results:
        logger.info(f"Returning cached results for {normalized_url}")
        return cached_results
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(normalized_url)
    hostname = parsed_url.netloc
    domain = tldextract.extract(hostname).registered_domain
    
    # Initialize results structure
    results = {
        "url": normalized_url,
        "safe": True,
        "alerts": [],
        "reputation_score": 100,
        "ssl_valid": False,
        "domain_age": "Inconnu",
        "redirects": [],
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 1. URL structure analysis
    structure_analysis = analyze_url_structure(normalized_url)
    results["alerts"].extend(structure_analysis["issues"])
    
    # 2. Check SSL certificate
    ssl_result = check_ssl_certificate(hostname)
    results["ssl_valid"] = ssl_result["valid"]
    results["alerts"].extend(ssl_result["issues"])
    
    # 3. Follow redirects
    redirect_chain = follow_redirects(normalized_url)
    results["redirects"] = redirect_chain
    
    # Check for suspicious redirects
    if len(redirect_chain) > 1:
        initial_domain = tldextract.extract(urllib.parse.urlparse(redirect_chain[0]["url"]).netloc).registered_domain
        final_domain = tldextract.extract(urllib.parse.urlparse(redirect_chain[-1]["url"]).netloc).registered_domain
        
        if initial_domain != final_domain:
            results["alerts"].append(f"URL redirects to a different domain: {final_domain}")
    
    # 4. Check domain reputation
    reputation = check_domain_reputation(domain)
    results["domain_age"] = f"{reputation['age_days']} jours" if reputation["age_days"] else "Inconnu"
    results["alerts"].extend(reputation["issues"])
    
    # 5. Analyze page content
    try:
        content_analysis = analyze_page_content(normalized_url)
        results["alerts"].extend(content_analysis["issues"])
        
        # Additional alerts based on content analysis
        if content_analysis["password_fields"] and structure_analysis["score"] < 70:
            results["alerts"].append("Password form on a suspicious domain")
        
        if content_analysis["forms"] and not ssl_result["valid"]:
            results["alerts"].append("Form submission on a non-HTTPS page")
    except Exception as e:
        logger.error(f"Error in content analysis: {e}")
    
    # Calculate overall reputation score
    structure_weight = 0.35
    ssl_weight = 0.20
    reputation_weight = 0.25
    content_weight = 0.20
    
    # Convert SSL valid to a score (100 if valid, 30 if not)
    ssl_score = 100 if ssl_result["valid"] else 30
    
    # Content analysis score (if we were able to analyze content)
    content_score = 100 - (len(content_analysis["issues"]) * 15) if "content_analysis" in locals() else 50
    content_score = max(0, min(100, content_score))
    
    # Calculate weighted score
    overall_score = (
        structure_analysis["score"] * structure_weight +
        ssl_score * ssl_weight +
        reputation["score"] * reputation_weight +
        content_score * content_weight
    )
    
    results["reputation_score"] = round(overall_score)
    
    # Determine if the URL is safe (score above 70 and no critical issues)
    critical_issues = ["Certificate has expired", "Listed on Spamhaus blocklist", 
                     "URL uses data: scheme", "Password field on a non-HTTPS page"]
    
    has_critical_issues = any(issue in results["alerts"] for issue in critical_issues)
    results["safe"] = results["reputation_score"] >= 70 and not has_critical_issues
    
    # Cache the results
    cache_results(cache_key, results)
    
    return results