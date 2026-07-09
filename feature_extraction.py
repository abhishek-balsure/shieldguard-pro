"""
Feature extraction utilities for phishing detection.

The original model used 25 lexical URL features. Newer training runs can append
external reputation and page-content signals while keeping the first 25 feature
positions stable for backward compatibility with the checked-in model artifact.
"""

import logging
import math
import os
import re
from functools import lru_cache
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = float(os.environ.get('URL_FEATURE_TIMEOUT_SECONDS', '3'))
ENABLE_EXTERNAL_URL_FEATURES = os.environ.get(
    'ENABLE_EXTERNAL_URL_FEATURES',
    'true'
).lower() in {'1', 'true', 'yes', 'on'}
FEATURE_USER_AGENT = os.environ.get(
    'URL_FEATURE_USER_AGENT',
    'ShieldGuard Pro Feature Extractor/1.0'
)
GOOGLE_SEARCH_URL = os.environ.get('GOOGLE_SEARCH_URL', 'https://www.google.com/search')
ALEXA_RANK_API_URL = os.environ.get('ALEXA_RANK_API_URL', 'https://data.alexa.com/data')
ALEXA_RANK_API_KEY = os.environ.get('ALEXA_RANK_API_KEY', '')
OPENPAGERANK_API_URL = os.environ.get(
    'OPENPAGERANK_API_URL',
    'https://openpagerank.com/api/v1.0/getPageRank'
)
OPENPAGERANK_API_KEY = os.environ.get('OPENPAGERANK_API_KEY', '')

BASE_FEATURES = [
    'url_length', 'hostname_length', 'has_https', 'has_ip', 'num_dots',
    'num_hyphens', 'num_underscores', 'num_slashes', 'num_questionmarks',
    'num_at', 'num_digits', 'num_subdomains', 'has_prefix_suffix',
    'suspicious_tld', 'has_suspicious_keywords', 'is_shortened', 'url_entropy',
    'digit_ratio', 'special_char_ratio', 'path_length', 'query_length',
    'num_equals', 'num_ampersands', 'has_port', 'brand_in_subdomain'
]

EXTERNAL_FEATURES = [
    'alexa_rank',
    'alexa_rank_normalized',
    'google_index',
    'google_results_count',
    'page_rank',
    'page_rank_normalized',
    'having_anchor_tag',
    'anchor_tag_count',
    'anchor_tag_ratio',
    'links_pointing_to_page',
]


def _extract_rank_value(payload):
    if isinstance(payload, dict):
        for key in ('rank', 'global_rank', 'alexa_rank', 'page_rank_decimal', 'page_rank_integer'):
            value = payload.get(key)
            if value not in (None, ''):
                try:
                    return float(value)
                except (TypeError, ValueError):
                    continue
        for value in payload.values():
            rank = _extract_rank_value(value)
            if rank is not None:
                return rank
    elif isinstance(payload, list):
        for item in payload:
            rank = _extract_rank_value(item)
            if rank is not None:
                return rank
    return None


def _clamp(value, lower=0.0, upper=1.0):
    return max(lower, min(upper, value))


def _normalize_rank(rank, ceiling):
    if rank is None or rank <= 0:
        return 0.0
    return round(_clamp(1.0 - min(rank, ceiling) / ceiling), 6)


def _extract_result_count(text):
    if not text:
        return 0
    match = re.search(r'([0-9][0-9,\.]*)\s+results', text, re.IGNORECASE)
    if not match:
        match = re.search(r'About\s+([0-9][0-9,\.]*)', text, re.IGNORECASE)
    if not match:
        return 0
    digits = re.sub(r'[^0-9]', '', match.group(1))
    return int(digits) if digits else 0


def _safe_hostname(parsed):
    hostname = parsed.netloc.lower().strip()
    if '@' in hostname:
        hostname = hostname.split('@', 1)[-1]
    if ':' in hostname:
        hostname = hostname.split(':', 1)[0]
    return hostname


@lru_cache(maxsize=2048)
def _get_http_response(url):
    if not ENABLE_EXTERNAL_URL_FEATURES:
        return None
    try:
        response = requests.get(
            url,
            headers={'User-Agent': FEATURE_USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()
        return response.text
    except Exception as exc:
        logger.debug("Page fetch failed for %s: %s", url, exc)
        return None


@lru_cache(maxsize=2048)
def _lookup_alexa_rank(hostname):
    if not ENABLE_EXTERNAL_URL_FEATURES or not hostname:
        return 0.0, 0.0

    headers = {'User-Agent': FEATURE_USER_AGENT}
    if ALEXA_RANK_API_KEY:
        headers['Authorization'] = f'Bearer {ALEXA_RANK_API_KEY}'

    try:
        response = requests.get(
            ALEXA_RANK_API_URL,
            params={'cli': '10', 'url': hostname},
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        rank = None

        if 'json' in content_type:
            rank = _extract_rank_value(response.json())
        else:
            match = re.search(r'TEXT="([0-9]+)"', response.text)
            if match:
                rank = float(match.group(1))

        if rank is None:
            return 0.0, 0.0
        return float(rank), _normalize_rank(rank, 10_000_000)
    except Exception as exc:
        logger.debug("Alexa rank lookup failed for %s: %s", hostname, exc)
        return 0.0, 0.0


@lru_cache(maxsize=2048)
def _lookup_google_index(hostname):
    if not ENABLE_EXTERNAL_URL_FEATURES or not hostname:
        return 0, 0

    try:
        response = requests.get(
            GOOGLE_SEARCH_URL,
            params={'q': f'site:{hostname}'},
            headers={'User-Agent': FEATURE_USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
        )
        response.raise_for_status()
        text = response.text
        not_found = (
            'did not match any documents' in text.lower() or
            'no results found' in text.lower()
        )
        count = _extract_result_count(text)
        indexed = 0 if not_found else int(count > 0 or 'href="/url?q=' in text)
        return indexed, count
    except Exception as exc:
        logger.debug("Google index lookup failed for %s: %s", hostname, exc)
        return 0, 0


@lru_cache(maxsize=2048)
def _lookup_page_rank(hostname):
    if not ENABLE_EXTERNAL_URL_FEATURES or not hostname or not OPENPAGERANK_API_KEY:
        return 0.0, 0.0

    try:
        response = requests.get(
            OPENPAGERANK_API_URL,
            params={'domains[]': hostname},
            headers={
                'User-Agent': FEATURE_USER_AGENT,
                'API-OPR': OPENPAGERANK_API_KEY,
            },
            timeout=DEFAULT_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        rank = _extract_rank_value(data)
        if rank is None:
            return 0.0, 0.0
        return float(rank), round(float(rank) / 10.0, 6)
    except Exception as exc:
        logger.debug("Page rank lookup failed for %s: %s", hostname, exc)
        return 0.0, 0.0


@lru_cache(maxsize=1024)
def _extract_page_content_features(url):
    if not ENABLE_EXTERNAL_URL_FEATURES:
        return {
            'having_anchor_tag': 0,
            'anchor_tag_count': 0,
            'anchor_tag_ratio': 0.0,
            'links_pointing_to_page': 0,
        }

    html = _get_http_response(url)
    if not html:
        return {
            'having_anchor_tag': 0,
            'anchor_tag_count': 0,
            'anchor_tag_ratio': 0.0,
            'links_pointing_to_page': 0,
        }

    try:
        soup = BeautifulSoup(html, 'html.parser')
        anchors = soup.find_all('a', href=True)
        anchor_count = len(anchors)
        parsed = urlparse(url)
        hostname = _safe_hostname(parsed)
        external_links = 0

        for anchor in anchors:
            target = anchor.get('href', '').strip()
            if not target or target.startswith('#') or target.lower().startswith('javascript:'):
                continue
            target_host = _safe_hostname(urlparse(urljoin(url, target)))
            if target_host and target_host != hostname:
                external_links += 1

        text_length = len(soup.get_text(" ", strip=True))
        anchor_ratio = anchor_count / max(text_length, 1)
        return {
            'having_anchor_tag': 1 if anchor_count > 0 else 0,
            'anchor_tag_count': anchor_count,
            'anchor_tag_ratio': round(anchor_ratio, 6),
            'links_pointing_to_page': external_links,
        }
    except Exception as exc:
        logger.debug("Anchor parsing failed for %s: %s", url, exc)
        return {
            'having_anchor_tag': 0,
            'anchor_tag_count': 0,
            'anchor_tag_ratio': 0.0,
            'links_pointing_to_page': 0,
        }


def extract_features(url, include_external=None):
    """
    Extract lexical and optional external features from a URL.
    """
    if not url or not isinstance(url, str):
        url = ""

    url = url.lower().strip()
    parsed = urlparse(url)
    hostname = _safe_hostname(parsed)
    path = parsed.path
    features = {}

    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)
    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$|(\d{1,3}\.){3}\d{1,3}(/|:)'
    features['has_ip'] = 1 if re.search(ip_pattern, hostname) else 0
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_questionmarks'] = url.count('?')
    features['num_at'] = url.count('@')
    features['num_digits'] = sum(char.isdigit() for char in url)

    if hostname:
        domain_parts = hostname.split('.')
        features['num_subdomains'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
    else:
        features['num_subdomains'] = 0

    features['has_prefix_suffix'] = 1 if '-' in hostname else 0
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz']
    features['suspicious_tld'] = 1 if any(hostname.endswith(tld) for tld in suspicious_tlds) else 0

    suspicious_keywords = [
        'verify', 'account', 'login', 'secure', 'update', 'confirm',
        'banking', 'password', 'credential', 'wallet', 'payment'
    ]
    features['has_suspicious_keywords'] = 1 if any(keyword in url for keyword in suspicious_keywords) else 0

    shorteners = [
        'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link',
        'is.gd', 'buff.ly', 'adf.ly', 'bitly.com'
    ]
    features['is_shortened'] = 1 if any(shortener in hostname for shortener in shorteners) else 0
    features['url_entropy'] = calculate_entropy(url)
    features['digit_ratio'] = features['num_digits'] / len(url) if url else 0

    special_chars = sum(1 for char in url if not char.isalnum())
    features['special_char_ratio'] = special_chars / len(url) if url else 0
    features['path_length'] = len(path)
    features['query_length'] = len(parsed.query)
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    features['has_port'] = 1 if ':' in parsed.netloc and not parsed.netloc.endswith(':') else 0

    brands = [
        'paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix',
        'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard'
    ]
    subdomain = '.'.join(hostname.split('.')[:-2]) if len(hostname.split('.')) > 2 else ""
    features['brand_in_subdomain'] = 1 if any(brand in subdomain for brand in brands) else 0

    use_external = ENABLE_EXTERNAL_URL_FEATURES if include_external is None else include_external
    if use_external:
        alexa_rank, alexa_rank_normalized = _lookup_alexa_rank(hostname)
        google_index, google_results_count = _lookup_google_index(hostname)
        page_rank, page_rank_normalized = _lookup_page_rank(hostname)
        content_features = _extract_page_content_features(url)
    else:
        alexa_rank = 0.0
        alexa_rank_normalized = 0.0
        google_index = 0
        google_results_count = 0
        page_rank = 0.0
        page_rank_normalized = 0.0
        content_features = {
            'having_anchor_tag': 0,
            'anchor_tag_count': 0,
            'anchor_tag_ratio': 0.0,
            'links_pointing_to_page': 0,
        }

    features['alexa_rank'] = alexa_rank
    features['alexa_rank_normalized'] = alexa_rank_normalized
    features['google_index'] = google_index
    features['google_results_count'] = google_results_count
    features['page_rank'] = page_rank
    features['page_rank_normalized'] = page_rank_normalized
    features.update(content_features)

    return features


def calculate_entropy(string):
    if not string:
        return 0.0

    probabilities = [float(string.count(char)) / len(string) for char in dict.fromkeys(list(string))]
    return -sum(probability * math.log(probability) / math.log(2.0) for probability in probabilities)


def get_feature_names():
    return BASE_FEATURES + EXTERNAL_FEATURES


def features_to_array(features_dict, feature_names=None):
    ordered_feature_names = feature_names or get_feature_names()
    return [features_dict.get(name, 0) for name in ordered_feature_names]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/login",
        "https://bit.ly/abc123",
        "http://verify-paypal-account.tk/login",
        "https://www.bankofamerica.com/secure/login"
    ]

    for test_url in test_urls:
        extracted = extract_features(test_url, include_external=False)
        print(f"\nURL: {test_url}")
        print(f"Feature count: {len(extracted)}")
        print(f"Features: {extracted}")
        print("-" * 80)
