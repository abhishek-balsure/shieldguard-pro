"""
Phishing Detection Web Application
A comprehensive Flask-based web application for detecting phishing URLs,
scanning emails and QR codes for malicious content.
"""

import os
import re
import pickle
import base64
import io
import csv
import json
import logging
import math
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin
from collections import Counter

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

import requests as http_requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, g, session, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import numpy as np

# Import local feature extraction module
from feature_extraction import extract_features, features_to_array, get_feature_names

# Try to import optional dependencies
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'shieldguard-pro-secret-key-2024')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'postgresql://shieldguard:shieldguard123@localhost:5432/shieldguarddb')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load the phishing detection model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
model = None
scaler = None

# Feature names expected by the model
MODEL_FEATURES = [
    'url_length', 'hostname_length', 'has_https', 'has_ip', 'num_dots',
    'num_hyphens', 'num_underscores', 'num_slashes', 'num_questionmarks',
    'num_at', 'num_digits', 'num_subdomains', 'has_prefix_suffix',
    'suspicious_tld', 'has_suspicious_keywords', 'is_shortened', 'url_entropy',
    'digit_ratio', 'special_char_ratio', 'path_length', 'query_length',
    'num_equals', 'num_ampersands', 'has_port', 'brand_in_subdomain'
]

try:
    with open(MODEL_PATH, 'rb') as f:
        model_data = pickle.load(f)
        if isinstance(model_data, dict):
            model = model_data.get('model')
            scaler = model_data.get('scaler')
        else:
            model = model_data
            scaler = None
    logger.info(f"Phishing detection model loaded successfully. Type: {type(model)}")
except FileNotFoundError:
    logger.warning("Model file not found. Predictions will not be available.")
except Exception as e:
    logger.error(f"Error loading model: {e}")

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db():
    """Get PostgreSQL database connection with RealDictCursor for dict-like row access."""
    if 'db' not in g:
        import psycopg2
        import psycopg2.extras
        g.db = psycopg2.connect(
            app.config['DATABASE_URL'],
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        g.db.autocommit = False
    return g.db


def close_db(e=None):
    """Close database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection after request."""
    close_db(exception)


def init_db():
    """Initialize PostgreSQL database with required tables."""
    import psycopg2
    try:
        conn = psycopg2.connect(app.config['DATABASE_URL'])
        cur = conn.cursor()

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence REAL,
                features TEXT,
                scan_type TEXT DEFAULT 'single',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS email_scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                sender TEXT,
                subject TEXT,
                content TEXT,
                urls_found TEXT,
                malicious_urls INTEGER DEFAULT 0,
                scan_result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS qr_scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                qr_data TEXT NOT NULL,
                is_url INTEGER DEFAULT 0,
                url_result TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS batch_scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                total_urls INTEGER,
                malicious_count INTEGER,
                safe_count INTEGER,
                file_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS message_scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                message_content TEXT,
                platform TEXT,
                urls_found INTEGER DEFAULT 0,
                malicious_count INTEGER DEFAULT 0,
                scan_result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS social_scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                url TEXT NOT NULL,
                platform TEXT,
                is_fake INTEGER DEFAULT 0,
                scan_result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS bookmarks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                url TEXT NOT NULL,
                result TEXT,
                confidence REAL,
                note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS achievements (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                badge_name TEXT NOT NULL,
                badge_description TEXT,
                badge_icon TEXT,
                earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create default admin user
        from werkzeug.security import generate_password_hash
        admin_hash = generate_password_hash('admin123')
        cur.execute('''
            INSERT INTO users (username, email, password, is_admin)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING
        ''', ('admin', 'admin@shieldguardpro.com', admin_hash, 1))

        conn.commit()
        cur.close()
        conn.close()
        logger.info("PostgreSQL database initialized successfully!")

    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

# ============================================================================
# ACHIEVEMENTS SYSTEM
# ============================================================================

ACHIEVEMENTS = [
    {'name': 'First Scan', 'description': 'Complete your first URL scan', 'icon': 'bi-rocket-takeoff', 'condition': lambda stats: stats.get('total_scans', 0) >= 1},
    {'name': 'URL Hunter', 'description': 'Scan 10 URLs', 'icon': 'bi-search', 'condition': lambda stats: stats.get('total_scans', 0) >= 10},
    {'name': 'Phishing Buster', 'description': 'Detect 5 phishing URLs', 'icon': 'bi-shield-exclamation', 'condition': lambda stats: stats.get('phishing_count', 0) >= 5},
    {'name': 'Email Guardian', 'description': 'Scan 5 emails', 'icon': 'bi-envelope-check', 'condition': lambda stats: stats.get('email_scans', 0) >= 5},
    {'name': 'QR Master', 'description': 'Scan 5 QR codes', 'icon': 'bi-qr-code-scan', 'condition': lambda stats: stats.get('qr_scans', 0) >= 5},
    {'name': 'Safety Expert', 'description': 'Detect 10 phishing URLs', 'icon': 'bi-award', 'condition': lambda stats: stats.get('phishing_count', 0) >= 10},
    {'name': 'Vigilant User', 'description': 'Save 5 bookmarks', 'icon': 'bi-bookmark-heart', 'condition': lambda stats: stats.get('bookmarks', 0) >= 5},
    {'name': 'Security Pro', 'description': 'Complete 50 scans', 'icon': 'bi-trophy', 'condition': lambda stats: stats.get('total_scans', 0) >= 50},
]


def check_and_award_achievements(user_id):
    """Check and award achievements based on user stats."""
    db = get_db()
    cur = db.cursor()
    stats = get_user_stats(user_id)

    cur.execute('SELECT COUNT(*) as count FROM bookmarks WHERE user_id = %s', (user_id,))
    stats['bookmarks'] = cur.fetchone()['count']

    cur.execute('SELECT badge_name FROM achievements WHERE user_id = %s', (user_id,))
    earned = cur.fetchall()
    earned_names = [r['badge_name'] for r in earned]

    new_badges = []
    for achievement in ACHIEVEMENTS:
        if achievement['name'] not in earned_names and achievement['condition'](stats):
            cur.execute('''
                INSERT INTO achievements (user_id, badge_name, badge_description, badge_icon)
                VALUES (%s, %s, %s, %s)
            ''', (user_id, achievement['name'], achievement['description'], achievement['icon']))
            new_badges.append(achievement)

    if new_badges:
        db.commit()

    return new_badges


def get_user_achievements(user_id):
    """Get all achievements for a user."""
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM achievements WHERE user_id = %s ORDER BY earned_at DESC', (user_id,))
    return cur.fetchall()


# Initialize database on startup
with app.app_context():
    init_db()


# ============================================================================
# DECORATORS
# ============================================================================

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT is_admin FROM users WHERE id = %s', (session['user_id'],))
        user = cur.fetchone()

        if not user or not user['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def extract_features_for_model(url):
    """
    Extract features from URL and return as numpy array for model prediction.
    Uses the shared feature_extraction module as single source of truth.
    """
    if not url:
        return np.zeros(len(MODEL_FEATURES)), {}

    features_dict = extract_features(url)
    feature_array = [features_dict.get(f, 0) for f in MODEL_FEATURES]
    return np.array(feature_array), features_dict


def check_urlhaus(url):
    """Cross-validate URL against URLhaus (abuse.ch)."""
    try:
        response = http_requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'found': data.get('query_status') == 'listed',
                'threat': data.get('threat', 'N/A'),
                'status': data.get('url_status', 'N/A'),
                'tags': data.get('tags', []),
                'source': 'URLhaus (abuse.ch)'
            }
    except Exception as e:
        logger.warning(f"URLhaus API check failed: {e}")
    return {'found': False, 'threat': 'N/A', 'status': 'N/A', 'tags': [], 'source': 'URLhaus (abuse.ch)'}


def check_phishtank(url):
    """Check URL against PhishTank database."""
    try:
        response = http_requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={'url': url, 'format': 'json'},
            headers={'User-Agent': 'ShieldGuard Pro/1.0'},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', {})
            return {
                'found': results.get('in_database', False),
                'is_phishing': results.get('valid', False),
                'verified': results.get('verified', False),
                'source': 'PhishTank'
            }
    except Exception as e:
        logger.warning(f"PhishTank check failed: {e}")
    return {'found': False, 'is_phishing': False, 'verified': False, 'source': 'PhishTank'}


def get_threat_intelligence(url):
    """Aggregate threat intelligence from free sources."""
    intel = {
        'urlhaus': check_urlhaus(url),
        'phishtank': check_phishtank(url),
        'total_sources': 2,
        'flagged_by': 0,
        'threat_level': 'low'
    }

    flagged = 0
    if intel['urlhaus']['found']:
        flagged += 1
    if intel['phishtank']['found'] and intel['phishtank']['is_phishing']:
        flagged += 1

    intel['flagged_by'] = flagged
    if flagged >= 2:
        intel['threat_level'] = 'critical'
    elif flagged == 1:
        intel['threat_level'] = 'high'
    else:
        intel['threat_level'] = 'low'

    return intel


FEATURE_DESCRIPTIONS = {
    'url_length': 'URL is unusually long',
    'hostname_length': 'Hostname is unusually long',
    'has_https': 'Missing HTTPS encryption',
    'has_ip': 'Contains IP address instead of domain',
    'num_dots': 'Unusually high number of dots in URL',
    'num_hyphens': 'Multiple hyphens in domain',
    'num_underscores': 'Contains underscores',
    'num_slashes': 'Unusually long path',
    'num_questionmarks': 'Contains query parameters',
    'num_at': 'Contains @ symbol (suspicious)',
    'num_digits': 'High digit-to-letter ratio',
    'num_subdomains': 'Excessive subdomains',
    'has_prefix_suffix': 'Hyphen in domain name',
    'suspicious_tld': 'Uses suspicious top-level domain (.tk, .xyz, etc.)',
    'has_suspicious_keywords': 'Contains suspicious keywords (verify, login, bank, etc.)',
    'is_shortened': 'Uses URL shortener service',
    'url_entropy': 'High URL entropy (random-looking characters)',
    'digit_ratio': 'High digit ratio',
    'special_char_ratio': 'High special character ratio',
    'path_length': 'Unusually long path',
    'query_length': 'Long query string',
    'num_equals': 'Contains many = signs (encoded data)',
    'num_ampersands': 'Contains many & signs',
    'has_port': 'Contains port number',
    'brand_in_subdomain': 'Brand name in subdomain (potential impersonation)'
}

SUSPICIOUS_FEATURES = {
    'has_ip': 'high',
    'num_at': 'high',
    'suspicious_tld': 'high',
    'is_shortened': 'medium',
    'brand_in_subdomain': 'high',
    'has_prefix_suffix': 'medium',
    'has_suspicious_keywords': 'medium'
}


def get_severity_level(confidence, suspicious_features):
    """Determine severity level based on confidence and suspicious features."""
    severity_score = confidence

    for feature, level in suspicious_features.items():
        if level == 'high':
            severity_score += 12
        elif level == 'medium':
            severity_score += 6

    if severity_score >= 80:
        return 'high'
    elif severity_score >= 50:
        return 'medium'
    else:
        return 'low'


def get_feature_importance(features_dict):
    """Analyze which features contributed most to the prediction."""
    importance = []

    for feature, value in features_dict.items():
        if feature in ['url_length', 'hostname_length', 'path_length', 'query_length']:
            if value > 75:
                importance.append({
                    'feature': feature.replace('_', ' ').title(),
                    'value': value,
                    'severity': 'high',
                    'description': FEATURE_DESCRIPTIONS.get(feature, feature)
                })
        elif feature in ['num_dots', 'num_hyphens', 'num_digits', 'num_slashes']:
            if value > 5:
                importance.append({
                    'feature': feature.replace('_', ' ').title(),
                    'value': value,
                    'severity': 'medium',
                    'description': FEATURE_DESCRIPTIONS.get(feature, feature)
                })
        elif value == 1:
            severity = SUSPICIOUS_FEATURES.get(feature, 'low')
            importance.append({
                'feature': feature.replace('_', ' ').title(),
                'value': value,
                'severity': severity,
                'description': FEATURE_DESCRIPTIONS.get(feature, feature)
            })

    severity_order = {'high': 0, 'medium': 1, 'low': 2}
    importance.sort(key=lambda x: severity_order.get(x['severity'], 2))
    return importance[:5]


def predict_url(url):
    """Predict if a URL is phishing or legitimate."""
    if model is None:
        return {
            'error': 'Model not loaded',
            'result': 'unknown',
            'confidence': 0.0,
            'features': {},
            'is_phishing': False,
            'is_legitimate': False
        }

    try:
        feature_array, features_dict = extract_features_for_model(url)
        feature_array = feature_array.reshape(1, -1)

        if scaler:
            feature_array = scaler.transform(feature_array)

        prediction = model.predict(feature_array)[0]

        try:
            probabilities = model.predict_proba(feature_array)[0]
            confidence = float(max(probabilities))
            prob_phishing = float(probabilities[1])
            prob_legitimate = float(probabilities[0])
        except:
            confidence = 0.85 if prediction == 1 else 0.85
            prob_phishing = 1.0 if prediction == 1 else 0.0
            prob_legitimate = 0.0 if prediction == 1 else 1.0

        result = 'phishing' if prediction == 1 else 'legitimate'

        feature_importance = []
        severity = 'none'

        if prediction == 1:
            feature_importance = get_feature_importance(features_dict)
            suspicious_features = {f['feature'].lower().replace(' ', '_'): f['severity'] for f in feature_importance}
            severity = get_severity_level(confidence * 100, suspicious_features)

        return {
            'result': result,
            'confidence': round(confidence * 100, 2),
            'features': features_dict,
            'is_phishing': prediction == 1,
            'is_legitimate': prediction == 0,
            'probability_phishing': round(prob_phishing * 100, 2),
            'probability_legitimate': round(prob_legitimate * 100, 2),
            'severity': severity,
            'feature_importance': feature_importance,
            'whois_info': get_whois_info(url),
            'ssl_info': get_ssl_info(url),
            'reputation': get_domain_reputation(url)
        }
    except Exception as e:
        logger.error(f"Error predicting URL {url}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            'error': str(e),
            'result': 'error',
            'confidence': 0.0,
            'features': {},
            'is_phishing': False,
            'is_legitimate': False,
            'severity': 'unknown',
            'feature_importance': []
        }


def save_scan(user_id, url, result_data, scan_type='single'):
    """Save scan result to database."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            INSERT INTO scans (user_id, url, result, confidence, features, scan_type)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (
            user_id,
            url,
            result_data.get('result', 'unknown'),
            result_data.get('confidence', 0.0),
            json.dumps(result_data.get('features', {})),
            scan_type
        ))
        db.commit()

        check_and_award_achievements(user_id)
    except Exception as e:
        logger.error(f"Error saving scan: {e}")


def get_user_stats(user_id):
    """Get statistics for a user."""
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT COUNT(*) as count FROM scans WHERE user_id = %s', (user_id,))
    total_scans = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s AND result = 'phishing'", (user_id,))
    phishing_count = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s AND result = 'legitimate'", (user_id,))
    safe_count = cur.fetchone()['count']

    cur.execute('SELECT COUNT(*) as count FROM email_scans WHERE user_id = %s', (user_id,))
    email_scans = cur.fetchone()['count']

    cur.execute('SELECT COUNT(*) as count FROM qr_scans WHERE user_id = %s', (user_id,))
    qr_scans = cur.fetchone()['count']

    return {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'email_scans': email_scans,
        'qr_scans': qr_scans
    }


def extract_urls_from_text(text):
    """Extract URLs from text content."""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


# ============================================================================
# ADVANCED ANALYSIS FEATURES
# ============================================================================

def get_whois_info(url):
    """Get Whois information for a domain."""
    if not WHOIS_AVAILABLE:
        return {'available': False, 'error': 'Whois module not available'}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if ':' in domain:
            domain = domain.split(':')[0]

        parts = domain.split('.')
        if len(parts) > 2:
            domain = '.'.join(parts[-2:])

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        domain_age_days = None
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        creation_date = datetime.strptime(creation_date.split(' ')[0], '%Y-%m-%d')
                    except:
                        creation_date = None

            if creation_date and isinstance(creation_date, datetime):
                domain_age_days = (datetime.now() - creation_date).days

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else 'Unknown'

        return {
            'available': True,
            'domain': domain,
            'registrar': registrar or 'Unknown',
            'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date and isinstance(creation_date, datetime) else str(creation_date) if creation_date else 'Unknown',
            'expiration_date': expiration_date.strftime('%Y-%m-%d') if expiration_date and isinstance(expiration_date, datetime) else str(expiration_date) if expiration_date else 'Unknown',
            'domain_age_days': domain_age_days,
            'domain_age_years': round(domain_age_days / 365, 1) if domain_age_days else None,
            'registrant': w.registrant_name if hasattr(w, 'registrant_name') else None,
            'country': w.country if hasattr(w, 'country') else None,
            'emails': w.emails if hasattr(w, 'emails') else None
        }
    except Exception as e:
        logger.warning(f"Whois lookup failed for {url}: {e}")
        return {'available': False, 'error': str(e)}


def get_ssl_info(url):
    """Analyze SSL certificate of a URL."""
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc

    if parsed.scheme != 'https':
        return {
            'available': True,
            'has_ssl': False,
            'valid': False,
            'issue': 'No HTTPS/SSL certificate'
        }

    try:
        import ssl
        import socket

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return {
                'available': True,
                'has_ssl': True,
                'valid': False,
                'issue': 'No certificate found'
            }

        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])

        not_before = datetime.strptime(cert['notBefore'].replace(' GMT', ''), '%b %d %H:%M:%S %Y')
        not_after = datetime.strptime(cert['notAfter'].replace(' GMT', ''), '%b %d %H:%M:%S %Y')

        days_until_expiry = (not_after - datetime.now()).days
        is_valid = datetime.now() >= not_before and datetime.now() <= not_after

        return {
            'available': True,
            'has_ssl': True,
            'valid': is_valid,
            'issuer': issuer.get('commonName', 'Unknown'),
            'subject': subject.get('commonName', hostname),
            'not_before': not_before.strftime('%Y-%m-%d'),
            'not_after': not_after.strftime('%Y-%m-%d'),
            'days_until_expiry': days_until_expiry,
            'version': cert.get('version', 'Unknown'),
            'serial_number': cert.get('serialNumber', 'Unknown')
        }
    except ssl.SSLCertVerificationError as e:
        return {
            'available': True,
            'has_ssl': True,
            'valid': False,
            'issue': f'Certificate verification failed: {str(e)}'
        }
    except Exception as e:
        logger.warning(f"SSL analysis failed for {url}: {e}")
        return {
            'available': True,
            'has_ssl': False,
            'valid': False,
            'issue': str(e)
        }


def get_domain_reputation(url):
    """Check domain reputation across multiple threat intelligence sources."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if ':' in domain:
        domain = domain.split(':')[0]

    parts = domain.split('.')
    if len(parts) > 2:
        domain = '.'.join(parts[-2:])

    reputation = {
        'domain': domain,
        'is_new_domain': None,
        'risk_signals': [],
        'safety_score': 100
    }

    try:
        whois_info = get_whois_info(url)
        if whois_info.get('available') and whois_info.get('domain_age_days'):
            age = whois_info['domain_age_days']
            reputation['is_new_domain'] = age < 90

            if age < 30:
                reputation['risk_signals'].append('Domain created within last 30 days')
                reputation['safety_score'] -= 30
            elif age < 90:
                reputation['risk_signals'].append('Domain created within last 90 days')
                reputation['safety_score'] -= 15

            if age > 365:
                reputation['safety_score'] += 10

        ssl_info = get_ssl_info(url)
        if ssl_info.get('available'):
            if not ssl_info.get('has_ssl'):
                reputation['risk_signals'].append('No SSL certificate')
                reputation['safety_score'] -= 20
            elif not ssl_info.get('valid'):
                reputation['risk_signals'].append('Invalid SSL certificate')
                reputation['safety_score'] -= 25
            elif ssl_info.get('days_until_expiry', 0) < 30:
                reputation['risk_signals'].append('SSL certificate expiring soon')
                reputation['safety_score'] -= 10

        if 'paypal' in domain.lower() or 'apple' in domain.lower() or 'google' in domain.lower() or 'microsoft' in domain.lower():
            if not any(brand in domain.lower() for brand in ['paypal.com', 'apple.com', 'google.com', 'microsoft.com']):
                reputation['risk_signals'].append('Possible brand impersonation')
                reputation['safety_score'] -= 40

        reputation['safety_score'] = max(0, min(100, reputation['safety_score']))

    except Exception as e:
        logger.warning(f"Reputation check failed: {e}")

    return reputation


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page."""
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT COUNT(*) as count FROM scans')
    total_scans = cur.fetchone()['count']

    cur.execute('SELECT COUNT(*) as count FROM users')
    total_users = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'")
    phishing_detected = cur.fetchone()['count']

    return render_template(
        'index.html',
        total_scans=total_scans,
        total_users=total_users,
        phishing_detected=phishing_detected
    )


@app.route('/quick_check', methods=['POST'])
def quick_check():
    """Quick URL check from homepage."""
    url = request.form.get('url', '').strip()

    if not url:
        flash('Please enter a URL.', 'warning')
        return redirect(url_for('index'))

    if not url.startswith(('http://', 'https://')):
        flash('Please enter a valid URL starting with http:// or https://', 'warning')
        return redirect(url_for('index'))

    result = predict_url(url)

    if 'user_id' in session:
        save_scan(session['user_id'], url, result, 'quick')

    return render_template('check_url.html', result=result, url=url, quick_check=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html')

        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])

            cur.execute('UPDATE users SET last_login = %s WHERE id = %s', (datetime.now(), user['id']))
            db.commit()

            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration."""
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('signup.html')

        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return render_template('signup.html')

        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter.', 'danger')
            return render_template('signup.html')

        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number.', 'danger')
            return render_template('signup.html')

        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('signup.html')

        db = get_db()
        cur = db.cursor()

        cur.execute('SELECT id FROM users WHERE username = %s', (username,))
        if cur.fetchone():
            flash('Username already taken.', 'danger')
            return render_template('signup.html')

        cur.execute('SELECT id FROM users WHERE email = %s', (email,))
        if cur.fetchone():
            flash('Email already registered.', 'danger')
            return render_template('signup.html')

        password_hash = generate_password_hash(password)
        cur.execute('''
            INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s)
        ''', (username, email, password_hash))
        db.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    stats = get_user_stats(session['user_id'])

    db = get_db()
    cur = db.cursor()

    cur.execute('''
        SELECT * FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    ''', (session['user_id'],))
    recent_scans = cur.fetchall()

    cur.execute('''
        SELECT * FROM bookmarks
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 5
    ''', (session['user_id'],))
    recent_bookmarks = cur.fetchall()

    today = datetime.now()
    dates = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    date_labels = [(today - timedelta(days=i)).strftime('%b %d') for i in range(6, -1, -1)]

    url_activity = []
    email_activity = []
    qr_activity = []

    for date in dates:
        cur.execute('''
            SELECT COUNT(*) as count FROM scans
            WHERE user_id = %s AND scan_type = 'single' AND DATE(created_at) = %s
        ''', (session['user_id'], date))
        url_activity.append(cur.fetchone()['count'] or 0)

        cur.execute('''
            SELECT COUNT(*) as count FROM email_scans
            WHERE user_id = %s AND DATE(created_at) = %s
        ''', (session['user_id'], date))
        email_activity.append(cur.fetchone()['count'] or 0)

        cur.execute('''
            SELECT COUNT(*) as count FROM qr_scans
            WHERE user_id = %s AND DATE(created_at) = %s
        ''', (session['user_id'], date))
        qr_activity.append(cur.fetchone()['count'] or 0)

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_scans=recent_scans,
        recent_bookmarks=recent_bookmarks,
        username=session.get('username'),
        activity_labels=date_labels,
        url_activity=url_activity,
        email_activity=email_activity,
        qr_activity=qr_activity
    )


@app.route('/check_url', methods=['GET', 'POST'])
@login_required
def check_url():
    """URL checking page."""
    result = None
    url = ''
    threat_intel = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            flash('Please enter a URL.', 'warning')
        elif not url.startswith(('http://', 'https://')):
            flash('Please enter a valid URL starting with http:// or https://', 'warning')
        else:
            result = predict_url(url)
            threat_intel = get_threat_intelligence(url)
            save_scan(session['user_id'], url, result, 'single')

    return render_template('check_url.html', result=result, url=url, threat_intel=threat_intel)


@app.route('/scanner')
@login_required
def scanner():
    """Unified scanner page with all scan types."""
    return render_template('scanner.html')


@app.route('/batch_check', methods=['GET', 'POST'])
@login_required
def batch_check():
    """Batch URL checking."""
    results = []

    if request.method == 'POST':
        urls_text = request.form.get('urls', '')
        file = request.files.get('file')

        urls = []

        if urls_text:
            urls = [url.strip() for url in urls_text.split('\n') if url.strip()]

        if file and file.filename:
            try:
                filename = secure_filename(file.filename)
                if filename.endswith('.csv'):
                    file_content = file.read()
                    if isinstance(file_content, bytes):
                        file_content = file_content.decode('utf-8')
                    reader = csv.DictReader(io.StringIO(file_content))
                    if 'url' in reader.fieldnames:
                        urls.extend([row['url'] for row in reader if row.get('url')])
                    else:
                        urls.extend([row[field] for row in reader for field in reader.fieldnames if row.get(field)])
                elif filename.endswith('.txt'):
                    content = file.read()
                    if isinstance(content, bytes):
                        content = content.decode('utf-8')
                    urls.extend([url.strip() for url in content.split('\n') if url.strip()])
            except Exception as e:
                flash(f'Error reading file: {e}', 'danger')

        if not urls:
            flash('Please enter URLs or upload a file.', 'warning')
        else:
            for url in urls[:100]:
                if url.startswith(('http://', 'https://')):
                    result = predict_url(url)
                    result['url'] = url
                    results.append(result)
                    save_scan(session['user_id'], url, result, 'batch')

            malicious_count = sum(1 for r in results if r.get('result') == 'phishing')
            safe_count = sum(1 for r in results if r.get('result') == 'legitimate')

            db = get_db()
            cur = db.cursor()
            cur.execute('''
                INSERT INTO batch_scans (user_id, total_urls, malicious_count, safe_count)
                VALUES (%s, %s, %s, %s)
            ''', (session['user_id'], len(results), malicious_count, safe_count))
            db.commit()

            return render_template(
                'batch_results.html',
                results=results,
                total=len(results),
                malicious=malicious_count,
                safe=safe_count
            )

    return render_template('batch.html')


@app.route('/email_scanner', methods=['GET', 'POST'])
@login_required
def email_scanner():
    """Email content scanner."""
    result = None

    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        content = request.form.get('content', '').strip()

        if not content:
            flash('Please enter email content.', 'warning')
        else:
            urls = extract_urls_from_text(content)

            malicious_urls = 0
            url_results = []

            for url in urls[:20]:
                prediction = predict_url(url)
                url_results.append({
                    'url': url,
                    'result': prediction.get('result'),
                    'confidence': prediction.get('confidence')
                })
                if prediction.get('result') == 'phishing':
                    malicious_urls += 1

            if malicious_urls > 0:
                overall_result = 'suspicious'
            elif len(urls) > 0:
                overall_result = 'safe'
            else:
                overall_result = 'no_urls'

            result = {
                'urls_found': len(urls),
                'malicious_urls': malicious_urls,
                'url_results': url_results,
                'overall_result': overall_result
            }

            db = get_db()
            cur = db.cursor()
            cur.execute('''
                INSERT INTO email_scans
                (user_id, sender, subject, content, urls_found, malicious_urls, scan_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                session['user_id'],
                sender,
                subject,
                content,
                json.dumps(urls),
                malicious_urls,
                overall_result
            ))
            db.commit()

    return render_template('email_scanner.html', result=result)


@app.route('/message_scanner', methods=['GET', 'POST'])
@login_required
def message_scanner():
    """SMS/WhatsApp message scanner."""
    result = None

    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        platform = request.form.get('platform', 'sms')

        if not message:
            flash('Please enter a message.', 'warning')
        else:
            urls = extract_urls_from_text(message)

            malicious_urls = 0
            safe_urls = 0
            url_results = []

            for url in urls[:20]:
                prediction = predict_url(url)
                url_results.append({
                    'url': url,
                    'result': prediction.get('result'),
                    'confidence': prediction.get('confidence')
                })
                if prediction.get('result') == 'phishing':
                    malicious_urls += 1
                else:
                    safe_urls += 1

            if malicious_urls > 0:
                overall_result = 'suspicious'
            elif len(urls) > 0:
                overall_result = 'safe'
            else:
                overall_result = 'no_urls'

            result = {
                'platform': platform,
                'message': message,
                'urls_found': len(urls),
                'malicious_urls': malicious_urls,
                'safe_urls': safe_urls,
                'url_results': url_results,
                'overall_result': overall_result
            }

            db = get_db()
            cur = db.cursor()
            cur.execute('''
                INSERT INTO message_scans (user_id, message_content, platform, urls_found, malicious_count, scan_result)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                session['user_id'],
                message,
                platform,
                len(urls),
                malicious_urls,
                overall_result
            ))
            db.commit()

    return render_template('message_scanner.html', result=result)


@app.route('/social_scanner', methods=['GET', 'POST'])
@login_required
def social_scanner():
    """Social media link scanner."""
    result = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            flash('Please enter a URL.', 'warning')
        elif not url.startswith(('http://', 'https://')):
            flash('Please enter a valid URL starting with http:// or https://', 'warning')
        else:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower().replace('www.', '')
            path = parsed.path.lower()

            detected_platform = None
            is_fake = False
            impersonation_signals = []

            social_keywords = {
                'facebook': ['facebook', 'fb.com', 'faceb00k', 'facebok', 'facenook'],
                'twitter': ['twitter', 'x.com', 'twiter', 'twittter', 'tweeter'],
                'instagram': ['instagram', 'instagraam', 'instgram', 'insragram', 'insta'],
                'linkedin': ['linkedin', 'linkdin', 'linkedln', 'linkden'],
                'whatsapp': ['whatsapp', 'watsapp', 'whatsap', 'wa.me'],
                'youtube': ['youtube', 'ytube', 'youtub', 'youtu.be'],
            }

            official_domains = {
                'facebook': ['facebook.com', 'fb.com', 'mbasic.facebook.com'],
                'twitter': ['twitter.com', 'x.com'],
                'instagram': ['instagram.com'],
                'linkedin': ['linkedin.com'],
                'whatsapp': ['whatsapp.com', 'wa.me'],
                'youtube': ['youtube.com', 'youtu.be'],
            }

            platform_info_map = {
                'facebook': {'name': 'Facebook', 'icon': 'bi-facebook'},
                'twitter': {'name': 'Twitter/X', 'icon': 'bi-twitter-x'},
                'instagram': {'name': 'Instagram', 'icon': 'bi-instagram'},
                'linkedin': {'name': 'LinkedIn', 'icon': 'bi-linkedin'},
                'whatsapp': {'name': 'WhatsApp', 'icon': 'bi-whatsapp'},
                'youtube': {'name': 'YouTube', 'icon': 'bi-youtube'},
            }

            for platform, keywords in social_keywords.items():
                for keyword in keywords:
                    if keyword in hostname:
                        detected_platform = platform
                        break
                if detected_platform:
                    break

            if detected_platform:
                doms = official_domains.get(detected_platform, [])
                if not any(dom in hostname for dom in doms):
                    impersonation_signals.append('Domain is not an official ' + platform_info_map[detected_platform]['name'] + ' domain')
                    is_fake = True

            if not detected_platform:
                if 'facebook' in hostname:
                    detected_platform = 'facebook'
                    is_fake = True
                    impersonation_signals.append('Suspicious Facebook-related domain')
                elif 'twitter' in hostname or 'x.com' in hostname:
                    detected_platform = 'twitter'
                    is_fake = True
                    impersonation_signals.append('Suspicious Twitter-related domain')
                elif 'instagram' in hostname:
                    detected_platform = 'instagram'
                    is_fake = True
                    impersonation_signals.append('Suspicious Instagram-related domain')
                elif 'linkedin' in hostname:
                    detected_platform = 'linkedin'
                    is_fake = True
                    impersonation_signals.append('Suspicious LinkedIn-related domain')
                else:
                    detected_platform = 'unknown'

            detected_info = platform_info_map.get(detected_platform, {'name': 'Unknown', 'icon': 'bi-globe'})

            prediction = predict_url(url)

            if prediction.get('result') == 'phishing' or is_fake:
                overall_result = 'suspicious'
            else:
                overall_result = 'safe'

            result = {
                'url': url,
                'platform': detected_platform,
                'platform_info': detected_info,
                'is_fake': is_fake,
                'impersonation_signals': impersonation_signals,
                'prediction': prediction,
                'overall_result': overall_result
            }

            db = get_db()
            cur = db.cursor()
            cur.execute('''
                INSERT INTO social_scans (user_id, url, platform, is_fake, scan_result)
                VALUES (%s, %s, %s, %s, %s)
            ''', (session['user_id'], url, detected_platform, int(is_fake), overall_result))
            db.commit()

    return render_template('social_scanner.html', result=result)


@app.route('/qr_scanner', methods=['GET', 'POST'])
@login_required
def qr_scanner():
    """QR code scanner."""
    result = None

    if request.method == 'POST':
        if 'qr_image' not in request.files:
            flash('No file uploaded.', 'warning')
            return render_template('qr_scanner.html')

        file = request.files['qr_image']

        if file.filename == '':
            flash('No file selected.', 'warning')
            return render_template('qr_scanner.html')

        if not QRCODE_AVAILABLE:
            flash('QR code scanning is not available. Please install required dependencies (Pillow, pyzbar).', 'danger')
            return render_template('qr_scanner.html')

        try:
            image = Image.open(file.stream)
            decoded_objects = decode(image)

            if not decoded_objects:
                flash('No QR code found in the image.', 'warning')
                return render_template('qr_scanner.html')

            qr_data = decoded_objects[0].data.decode('utf-8')
            is_url = qr_data.startswith(('http://', 'https://'))

            url_result = None
            confidence = None

            if is_url:
                prediction = predict_url(qr_data)
                url_result = prediction.get('result')
                confidence = prediction.get('confidence')

            result = {
                'qr_data': qr_data,
                'is_url': is_url,
                'url_result': url_result,
                'confidence': confidence
            }

            db = get_db()
            cur = db.cursor()
            cur.execute('''
                INSERT INTO qr_scans
                (user_id, qr_data, is_url, url_result, confidence)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                session['user_id'],
                qr_data,
                int(is_url),
                url_result,
                confidence
            ))
            db.commit()

        except Exception as e:
            logger.error(f"Error processing QR code: {e}")
            flash(f'Error processing image: {e}', 'danger')

    return render_template('qr_scanner.html', result=result)


@app.route('/history')
@login_required
def history():
    """View scan history."""
    db = get_db()
    cur = db.cursor()

    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = 'SELECT * FROM scans WHERE user_id = %s'
    params = [session['user_id']]

    if search:
        query += ' AND url LIKE %s'
        params.append(f'%{search}%')

    if filter_type == 'phishing':
        query += " AND result = 'phishing'"
    elif filter_type == 'legitimate':
        query += " AND result = 'legitimate'"

    count_query = query.replace('SELECT *', 'SELECT COUNT(*) as count')
    cur.execute(count_query, params)
    total = cur.fetchone()['count']

    query += ' ORDER BY created_at DESC LIMIT %s OFFSET %s'
    params.extend([per_page, (page - 1) * per_page])

    cur.execute(query, params)
    scans = cur.fetchall()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'history.html',
        scans=scans,
        search=search,
        filter_type=filter_type,
        page=page,
        total_pages=total_pages,
        total=total
    )


@app.route('/history/export/csv')
@login_required
def export_history_csv():
    """Export scan history as CSV."""
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        SELECT url, result, confidence, scan_type, created_at
        FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
    ''', (session['user_id'],))
    scans = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Result', 'Confidence (%)', 'Scan Type', 'Date'])

    for scan in scans:
        writer.writerow([
            scan['url'],
            scan['result'],
            f"{scan['confidence']:.2f}",
            scan['scan_type'],
            scan['created_at']
        ])

    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=scan_history.csv'}
    )


@app.route('/history/export/pdf')
@login_required
def export_history_pdf():
    """Export scan history as PDF report."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import inch
    except ImportError:
        flash('PDF export not available. Please install reportlab.', 'warning')
        return redirect(url_for('history'))

    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()

    cur.execute('''
        SELECT url, result, confidence, scan_type, created_at
        FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 50
    ''', (session['user_id'],))
    scans = cur.fetchall()

    stats = get_user_stats(session['user_id'])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, spaceAfter=30, textColor=colors.HexColor('#1a1a2e'))
    story.append(Paragraph("ShieldGuard Pro - Scan Report", title_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph(f"<b>User:</b> {user['username']}", styles['Normal']))
    story.append(Paragraph(f"<b>Email:</b> {user['email']}", styles['Normal']))
    story.append(Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Summary Statistics</b>", styles['Heading2']))
    stats_data = [
        ['Total Scans', 'Phishing Detected', 'Safe URLs', 'Accuracy'],
        [str(stats.get('total_scans', 0)), str(stats.get('phishing_count', 0)), str(stats.get('safe_count', 0)), '95%+']
    ]
    t = Table(stats_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(t)
    story.append(Spacer(1, 30))

    story.append(Paragraph("<b>Recent Scans</b>", styles['Heading2']))
    scan_data = [['URL', 'Result', 'Confidence', 'Date']]
    for scan in scans:
        scan_data.append([
            scan['url'][:40] + '...' if len(scan['url']) > 40 else scan['url'],
            scan['result'].upper(),
            f"{scan['confidence']:.1f}%",
            str(scan['created_at'])[:10]
        ])

    if len(scan_data) > 1:
        t2 = Table(scan_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.2*inch])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        story.append(t2)

    story.append(Spacer(1, 30))
    story.append(Paragraph("<i>Generated by ShieldGuard Pro - AI-Powered Phishing Detection</i>", styles['Normal']))

    doc.build(story)
    buffer.seek(0)

    return Response(
        buffer,
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=scan_report.pdf'}
    )


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile and settings."""
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()

    stats = get_user_stats(session['user_id'])

    cur.execute('''
        SELECT * FROM bookmarks
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    ''', (session['user_id'],))
    recent_bookmarks = cur.fetchall()

    cur.execute('''
        SELECT * FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    ''', (session['user_id'],))
    recent_scans = cur.fetchall()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()

            if username and email:
                if username != user['username']:
                    cur.execute('SELECT id FROM users WHERE username = %s AND id != %s', (username, session['user_id']))
                    if cur.fetchone():
                        flash('Username already taken.', 'danger')
                        return render_template('profile.html', user=user)

                if email != user['email']:
                    cur.execute('SELECT id FROM users WHERE email = %s AND id != %s', (email, session['user_id']))
                    if cur.fetchone():
                        flash('Email already registered.', 'danger')
                        return render_template('profile.html', user=user)

                cur.execute('UPDATE users SET username = %s, email = %s WHERE id = %s',
                           (username, email, session['user_id']))
                db.commit()
                session['username'] = username
                flash('Profile updated successfully!', 'success')

                cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
                user = cur.fetchone()

        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'danger')
            else:
                password_hash = generate_password_hash(new_password)
                cur.execute('UPDATE users SET password = %s WHERE id = %s', (password_hash, session['user_id']))
                db.commit()
                flash('Password changed successfully!', 'success')

        cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cur.fetchone()

    achievements = get_user_achievements(session['user_id'])
    total_possible = len(ACHIEVEMENTS)
    earned_count = len(achievements)

    return render_template('profile.html', user=user, stats=stats, recent_bookmarks=recent_bookmarks, recent_scans=recent_scans, achievements=achievements, total_achievements=total_possible, earned_achievements=earned_count)


@app.route('/bookmarks')
@login_required
def bookmarks():
    """View bookmarked URLs."""
    db = get_db()
    cur = db.cursor()
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    query = 'SELECT * FROM bookmarks WHERE user_id = %s'
    params = [session['user_id']]

    if search:
        query += ' AND url LIKE %s'
        params.append(f'%{search}%')

    if filter_type == 'phishing':
        query += " AND result = 'phishing'"
    elif filter_type == 'legitimate':
        query += " AND result = 'legitimate'"

    count_query = query.replace('SELECT *', 'SELECT COUNT(*) as count')
    cur.execute(count_query, params)
    total = cur.fetchone()['count']

    query += ' ORDER BY created_at DESC LIMIT %s OFFSET %s'
    params.extend([per_page, (page - 1) * per_page])

    cur.execute(query, params)
    bookmarks_list = cur.fetchall()
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'bookmarks.html',
        bookmarks=bookmarks_list,
        search=search,
        filter_type=filter_type,
        page=page,
        total_pages=total_pages,
        total=total
    )


@app.route('/bookmark/add', methods=['POST'])
@login_required
def add_bookmark():
    """Add URL to bookmarks."""
    url = request.form.get('url', '').strip()
    result = request.form.get('result', '')
    confidence = request.form.get('confidence', 0)
    note = request.form.get('note', '')

    if url:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            INSERT INTO bookmarks (user_id, url, result, confidence, note)
            VALUES (%s, %s, %s, %s, %s)
        ''', (session['user_id'], url, result, confidence, note))
        db.commit()
        flash('URL bookmarked successfully!', 'success')

    return redirect(request.referrer or url_for('dashboard'))


@app.route('/bookmark/<int:bookmark_id>/delete', methods=['POST'])
@login_required
def delete_bookmark(bookmark_id):
    """Delete a bookmark."""
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM bookmarks WHERE id = %s AND user_id = %s',
               (bookmark_id, session['user_id']))
    db.commit()
    flash('Bookmark deleted.', 'success')
    return redirect(url_for('bookmarks'))


@app.route('/bookmark/<int:bookmark_id>/rescan')
@login_required
def rescan_bookmark(bookmark_id):
    """Rescan a bookmarked URL."""
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM bookmarks WHERE id = %s AND user_id = %s',
               (bookmark_id, session['user_id']))
    bookmark = cur.fetchone()

    if bookmark:
        result = predict_url(bookmark['url'])
        save_scan(session['user_id'], bookmark['url'], result, 'rescan')
        flash(f'Rescan complete: {result["result"]} ({result["confidence"]}%)',
              'success' if result['result'] == 'legitimate' else 'warning')

    return redirect(url_for('bookmarks'))


@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard."""
    db = get_db()
    cur = db.cursor()

    search = request.args.get('search', '')
    user_filter = request.args.get('filter', 'all')

    cur.execute('SELECT COUNT(*) as count FROM users')
    total_users = cur.fetchone()['count']

    cur.execute('SELECT COUNT(*) as count FROM scans')
    total_scans = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'")
    total_phishing = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE result = 'legitimate'")
    total_legitimate = cur.fetchone()['count']

    query = '''
        SELECT u.*, COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
    '''
    params = []
    if search:
        query += ' WHERE u.username LIKE %s OR u.email LIKE %s'
        params = [f'%{search}%', f'%{search}%']

    query += ' GROUP BY u.id ORDER BY u.created_at DESC'

    cur.execute(query, params)
    users = cur.fetchall()

    cur.execute('''
        SELECT s.*, u.username
        FROM scans s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 50
    ''')
    recent_scans = cur.fetchall()

    cur.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM scans
        WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY date DESC
    ''')
    scans_per_day = cur.fetchall()

    cur.execute('''
        SELECT TO_CHAR(created_at, 'YYYY-MM') as month, COUNT(*) as count
        FROM scans
        WHERE created_at >= CURRENT_DATE - INTERVAL '6 months'
        GROUP BY TO_CHAR(created_at, 'YYYY-MM')
        ORDER BY month DESC
    ''')
    scans_per_month = cur.fetchall()

    cur.execute('''
        SELECT u.id, u.username, COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
        GROUP BY u.id
        ORDER BY scan_count DESC
        LIMIT 5
    ''')
    top_users = cur.fetchall()

    cur.execute('''
        SELECT COUNT(*) as count FROM users
        WHERE DATE(created_at) = CURRENT_DATE
    ''')
    new_users_today = cur.fetchone()['count']

    cur.execute('''
        SELECT COUNT(*) as count FROM scans
        WHERE DATE(created_at) = CURRENT_DATE
    ''')
    scans_today = cur.fetchone()['count']

    return render_template(
        'admin.html',
        total_users=total_users,
        total_scans=total_scans,
        total_phishing=total_phishing,
        total_legitimate=total_legitimate,
        users=users,
        recent_scans=recent_scans,
        scans_per_day=scans_per_day,
        scans_per_month=scans_per_month,
        top_users=top_users,
        new_users_today=new_users_today,
        scans_today=scans_today,
        search=search
    )


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user."""
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin'))

    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
    db.commit()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    """Toggle admin status for a user."""
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()

    if user:
        new_status = 0 if user['is_admin'] else 1
        cur.execute('UPDATE users SET is_admin = %s WHERE id = %s', (new_status, user_id))
        db.commit()
        flash('User admin status updated.', 'success')

    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """View user details and scan history."""
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin'))

    cur.execute('SELECT COUNT(*) as count FROM scans WHERE user_id = %s', (user_id,))
    total_scans = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s AND result = 'phishing'", (user_id,))
    phishing_count = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s AND result = 'legitimate'", (user_id,))
    safe_count = cur.fetchone()['count']

    stats = {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count
    }

    cur.execute('''
        SELECT * FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 50
    ''', (user_id,))
    scans = cur.fetchall()

    return render_template(
        'admin_user_detail.html',
        user=user,
        stats=stats,
        scans=scans
    )


@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')


@app.route('/help')
def help_page():
    """Help and FAQ page."""
    return render_template('help.html')


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/check_url', methods=['POST'])
def api_check_url():
    """API endpoint to check a single URL."""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Invalid URL format. URL must start with http:// or https://'}), 400

    result = predict_url(url)

    if 'error' in result:
        return jsonify({'error': result['error']}), 500

    return jsonify({
        'url': url,
        'result': result['result'],
        'confidence': result['confidence'],
        'is_phishing': result['is_phishing'],
        'is_legitimate': result['is_legitimate'],
        'features': result['features']
    })


@app.route('/api/batch_check', methods=['POST'])
def api_batch_check():
    """API endpoint to check multiple URLs."""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    urls = data.get('urls', [])

    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'URLs array is required'}), 400

    if len(urls) > 100:
        return jsonify({'error': 'Maximum 100 URLs allowed per request'}), 400

    results = []

    for url in urls:
        if url.startswith(('http://', 'https://')):
            prediction = predict_url(url)
            results.append({
                'url': url,
                'result': prediction.get('result'),
                'confidence': prediction.get('confidence'),
                'is_phishing': prediction.get('is_phishing'),
                'is_legitimate': prediction.get('is_legitimate'),
                'error': prediction.get('error')
            })
        else:
            results.append({
                'url': url,
                'error': 'Invalid URL format'
            })

    return jsonify({
        'total': len(urls),
        'results': results
    })


@app.route('/api/stats')
def api_stats():
    """API endpoint to get system statistics."""
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT COUNT(*) as count FROM users')
    total_users = cur.fetchone()['count']

    cur.execute('SELECT COUNT(*) as count FROM scans')
    total_scans = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'")
    phishing_detected = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM scans WHERE result = 'legitimate'")
    legitimate_detected = cur.fetchone()['count']

    stats = {
        'total_users': total_users,
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'legitimate_detected': legitimate_detected
    }

    return jsonify(stats)


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    if request.is_json:
        return jsonify({'error': 'Not found'}), 404
    flash('Page not found.', 'warning')
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    flash('An internal error occurred. Please try again.', 'danger')
    return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(error):
    """Handle file too large error."""
    flash('File too large. Maximum size is 16MB.', 'danger')
    return redirect(request.url)


# ============================================================================
# MULTI-LANGUAGE SUPPORT
# ============================================================================

TRANSLATIONS = {
    'hi': {
        'home': 'होम',
        'dashboard': 'डैशबोर्ड',
        'scanners': 'स्कैनर',
        'url_scanner': 'URL स्कैनर',
        'email_scanner': 'ईमेल स्कैनर',
        'message_scanner': 'मैसेज स्कैनर',
        'qr_scanner': 'QR स्कैनर',
        'batch_check': 'बैच चेक',
        'history': 'इतिहास',
        'bookmarks': 'बुकमार्क',
        'profile': 'प्रोफ़ाइल',
        'login': 'लॉगिन',
        'signup': 'साइन अप',
        'logout': 'लॉगआउट',
        'admin': 'एडमिन',
        'about': 'के बारे में',
        'help': 'मदद',
        'shieldguard_pro': 'शील्डगार्ड प्रो',
        'scan_now': 'अभी स्कैन करें',
        'welcome_back': 'वापसी पर स्वागत है',
        'email': 'ईमेल',
        'password': 'पासवर्ड',
        'url': 'URL',
        'results': 'परिणाम',
        'safe': 'सुरक्षित',
        'phishing': 'फ़िशिंग',
        'confidence': 'विश्वास',
        'scan_results': 'स्कैन परिणाम',
        'features': 'विशेषताएं',
    }
}


def get_translation(key, lang='en'):
    """Get translation for a given language."""
    return TRANSLATIONS.get(lang, {}).get(key, key)


@app.context_processor
def inject_globals():
    """Inject global variables into templates."""
    lang = session.get('lang', 'en')
    if lang not in TRANSLATIONS:
        lang = 'en'
    return {
        'now': datetime.now(),
        'datetime': datetime,
        'app_name': 'ShieldGuard Pro',
        'version': '1.0.0',
        'current_lang': lang,
        't': lambda key: get_translation(key, lang)
    }


@app.before_request
def store_language():
    """Ensure lang is in session."""
    if 'lang' not in session:
        session['lang'] = 'en'


@app.route('/set_lang/<lang>')
def set_lang(lang):
    """Set language via URL and redirect."""
    if lang not in TRANSLATIONS:
        lang = 'en'
    session['lang'] = lang
    ref = request.referrer or url_for('index')
    return redirect(ref)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        init_db()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
        threaded=True
    )