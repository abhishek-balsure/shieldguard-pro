"""
Feature Extraction Module for Phishing Detection
Extracts 20+ features from URLs for machine learning classification
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter


def extract_features(url):
    """
    Extract 20+ features from a URL for phishing detection.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing all extracted features
    """
    if not url or not isinstance(url, str):
        url = ""
    
    url = url.lower().strip()
    
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    features = {}
    
    # 1. URL length
    features['url_length'] = len(url)
    
    # 2. Hostname length
    features['hostname_length'] = len(hostname)
    
    # 3. Has HTTPS
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    
    # 4. Has IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$|(\d{1,3}\.){3}\d{1,3}(/|:)'
    features['has_ip'] = 1 if re.search(ip_pattern, hostname) else 0
    
    # 5. Number of dots
    features['num_dots'] = url.count('.')
    
    # 6. Number of hyphens
    features['num_hyphens'] = url.count('-')
    
    # 7. Number of underscores
    features['num_underscores'] = url.count('_')
    
    # 8. Number of slashes
    features['num_slashes'] = url.count('/')
    
    # 9. Number of question marks
    features['num_questionmarks'] = url.count('?')
    
    # 10. Number of @ symbols
    features['num_at'] = url.count('@')
    
    # 11. Number of digits
    features['num_digits'] = sum(c.isdigit() for c in url)
    
    # 12. Number of subdomains
    if hostname:
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            features['num_subdomains'] = len(domain_parts) - 2
        else:
            features['num_subdomains'] = 0
    else:
        features['num_subdomains'] = 0
    
    # 13. Has prefix-suffix (hyphen in domain)
    features['has_prefix_suffix'] = 1 if '-' in hostname else 0
    
    # 14. Suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz']
    features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
    
    # 15. Has suspicious keywords
    suspicious_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm', 
                          'banking', 'password', 'credential', 'wallet', 'payment']
    features['has_suspicious_keywords'] = 1 if any(keyword in url for keyword in suspicious_keywords) else 0
    
    # 16. Is shortened URL
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link', 
                  'is.gd', 'buff.ly', 'adf.ly', 'bitly.com']
    features['is_shortened'] = 1 if any(shortener in hostname for shortener in shorteners) else 0
    
    # 17. URL entropy (Shannon entropy)
    features['url_entropy'] = calculate_entropy(url)
    
    # 18. Digit ratio
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
    
    # 19. Special character ratio
    special_chars = sum(1 for c in url if not c.isalnum())
    features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
    
    # 20. Path length
    features['path_length'] = len(path)
    
    # 21. Query length
    features['query_length'] = len(parsed.query)
    
    # 22. Number of equals signs
    features['num_equals'] = url.count('=')
    
    # 23. Number of ampersands
    features['num_ampersands'] = url.count('&')
    
    # 24. Has port number
    features['has_port'] = 1 if ':' in hostname and not hostname.endswith(':') else 0
    
    # 25. Brand name in subdomain (potential phishing)
    brands = ['paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix',
              'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
    subdomain = '.'.join(hostname.split('.')[:-2]) if len(hostname.split('.')) > 2 else ""
    features['brand_in_subdomain'] = 1 if any(brand in subdomain for brand in brands) else 0
    
    return features


def calculate_entropy(string):
    """
    Calculate Shannon entropy of a string.
    
    Args:
        string (str): Input string
        
    Returns:
        float: Shannon entropy value
    """
    if not string:
        return 0.0
    
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def get_feature_names():
    """
    Get list of feature names in consistent order.
    
    Returns:
        list: Ordered list of feature names
    """
    return [
        'url_length', 'hostname_length', 'has_https', 'has_ip', 'num_dots',
        'num_hyphens', 'num_underscores', 'num_slashes', 'num_questionmarks',
        'num_at', 'num_digits', 'num_subdomains', 'has_prefix_suffix',
        'suspicious_tld', 'has_suspicious_keywords', 'is_shortened', 'url_entropy',
        'digit_ratio', 'special_char_ratio', 'path_length', 'query_length',
        'num_equals', 'num_ampersands', 'has_port', 'brand_in_subdomain'
    ]


def features_to_array(features_dict):
    """
    Convert features dictionary to array for ML model.
    
    Args:
        features_dict (dict): Dictionary of features
        
    Returns:
        list: Array of feature values in consistent order
    """
    feature_names = get_feature_names()
    return [features_dict.get(f, 0) for f in feature_names]


# Test the module
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/login",
        "https://bit.ly/abc123",
        "http://verify-paypal-account.tk/login",
        "https://www.bankofamerica.com/secure/login"
    ]
    
    for url in test_urls:
        features = extract_features(url)
        print(f"\nURL: {url}")
        print(f"Features: {features}")
        print("-" * 80)
