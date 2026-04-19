<!-- PROJECT_NAME_START -->
# 🔒 ShieldGuard Pro - AI-Powered Phishing Detection

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-black?style=flat&logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.6+-orange?style=flat)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](https://opensource.org/licenses/MIT)
[![Stars](https://img.shields.io/github/stars/abhishek-balsure/phishing-detector-pro?style=flat)](https://github.com/abhishek-balsure/phishing-detector-pro/stargazers)

A comprehensive ML-powered web application for detecting phishing URLs, emails, and QR codes in real-time with 95%+ accuracy.

---

## ✨ Features

### 🔍 Scanning Modes
- **URL Scanner** - Analyze any URL for phishing indicators using Machine Learning
- **Batch Checker** - Scan multiple URLs at once (CSV/text file upload)
- **Email Scanner** - Extract and analyze URLs from email content
- **QR Code Scanner** - Decode QR codes and verify embedded URLs

### 🎯 Core Capabilities
- **25+ URL Features** - Comprehensive feature extraction including domain analysis, URL structure, and content patterns
- **Real-time Detection** - Instant phishing detection with confidence scores
- **Threat Intelligence** - Cross-validation with known malware databases
- **Severity Levels** - Low/Medium/High risk classification with explainable AI
- **Whois & SSL Analysis** - Domain age and certificate verification

### 👤 User Features
- **User Authentication** - Secure registration and login system
- **Dashboard** - Personal statistics and scan history
- **Bookmarks** - Save suspicious URLs for later analysis
- **Achievement Badges** - Gamification with badges for active users
- **Password Validation** - Strong password requirements (8+ chars, uppercase, lowercase, number)

### 🛠 Admin Features
- **Admin Panel** - System-wide statistics and user management
- **User Analytics** - Track usage patterns and threat trends

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 95%+ |
| **Precision** | 94%+ |
| **Recall** | 96%+ |
| **F1-Score** | 95%+ |
| **AUC-ROC** | 98%+ |

### Technical Details
- **Algorithm**: Random Forest Classifier (100 decision trees)
- **Features**: 25+ URL-based features extracted
- **Training Data**: 50,000+ URLs (legitimate + phishing)
- **Pre-trained**: Model ready to use - no training required

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| **Backend** | Python 3.11+, Flask 3.0+ |
| **ML/AI** | scikit-learn (Random Forest) |
| **Database** | SQLite |
| **Frontend** | HTML5, CSS3, Bootstrap 5, JavaScript |
| **Deployment** | Gunicorn, Render |

---

## 📦 Installation

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Local Development

1. **Clone the repository**
```bash
git clone https://github.com/abhishek-balsure/phishing-detector-pro.git
cd phishing-detector-pro
```

2. **Create virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Run the application**
```bash
python app.py
```

6. **Open browser**
```
http://localhost:5000
```

### Deploy to Render (Free)

1. Push code to GitHub
2. Create a new Web Service on [render.com](https://render.com)
3. Connect your GitHub repository
4. Set:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   - Python Version: 3.11
5. Deploy!

---

## 🔄 How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   User      │────▶│  URL Feature     │────▶│     ML Model    │
│   Input     │     │  Extraction      │     │   (Random       │
│  (URL/QR)   │     │  (25+ features) │     │   Forest)       │
└─────────────┘     └──────────────────┘     └────────┬────────┘
                                                        │
                        ┌──────────────────┐             │
                        │  Whois & SSL    │◀────────────┘
                        │  Analysis       │
                        └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │   Result:        │
                        │   Phishing/Safe  │
                        │   + Confidence   │
                        └──────────────────┘
```

### Detection Process

1. **Input** - User provides URL, email, or QR code
2. **Feature Extraction** - 25+ features extracted (URL length, domain entropy, TLD analysis, etc.)
3. **ML Prediction** - Random Forest classifier analyzes features
4. **Whois/SSL** - Domain age and certificate verification
5. **Result** - Displays prediction with confidence score and explanation

---

## 📁 Project Structure

```
phishing-detector-pro/
├── app.py                      # Main Flask application
├── feature_extraction.py       # URL feature extraction module
├── train_model.py              # Model training script (for future use)
├── requirements.txt           # Python dependencies
├── phishing_model.pkl          # Pre-trained ML model
├── phishing_detection.db       # SQLite database
├── Procfile                    # Render deployment config
├── runtime.txt                 # Python version config
│
├── templates/                  # HTML templates
│   ├── base.html               # Base template
│   ├── index.html              # Homepage
│   ├── login.html              # Login page
│   ├── signup.html             # Signup page
│   ├── scanner.html            # URL scanner
│   ├── check_url.html          # Scan results
│   ├── batch.html              # Batch scanner
│   ├── email_scanner.html      # Email scanner
│   ├── qr_scanner.html         # QR scanner
│   ├── profile.html            # User profile
│   ├── dashboard.html          # User dashboard
│   ├── history.html            # Scan history
│   ├── bookmarks.html          # Saved URLs
│   ├── admin.html              # Admin panel
│   └── ...
│
└── static/                     # Static assets
    ├── css/
    │   ├── style.css           # Main styles
    │   └── animations.css      # Animations
    └── js/
        └── main.js             # JavaScript
```

---

## 🔐 Default Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `Abhishek@436`

> ⚠️ **Security Note**: Change the admin password after first login!

---

## 🔐 Security Features

- Password hashing with Werkzeug
- Session-based authentication
- SQL injection prevention
- Strong password validation (8+ chars, uppercase, lowercase, number)
- Input validation and sanitization

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- [scikit-learn](https://scikit-learn.org/) - Machine learning library
- [Bootstrap](https://getbootstrap.com/) - CSS framework

---

<div align="center">

**Made with ❤️ for a safer internet**

⭐ Star this repo if you found it useful!

</div>

<!-- PROJECT_NAME_END -->