# ShieldGuard Pro

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-black?style=flat&logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-abhiishek25%2Fshieldguard--pro-2496ED?style=flat&logo=docker&logoColor=white)](https://hub.docker.com/r/abhiishek25/shieldguard-pro)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-CI%2FCD-2088FF?style=flat&logo=githubactions&logoColor=white)](https://github.com/abhishek-balsure/phishing-detector-pro/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](https://opensource.org/licenses/MIT)

ShieldGuard Pro is an enterprise-grade phishing detection platform powered by machine learning. It combines advanced URL analysis with comprehensive security features including OAuth authentication, real-time threat detection, and professional UI/UX.

## Live Links

- Application: [http://35.154.32.25:5000](http://35.154.32.25:5000)
- Docker Hub: [https://hub.docker.com/r/abhiishek25/shieldguard-pro](https://hub.docker.com/r/abhiishek25/shieldguard-pro)
- GitHub Actions: [Repository workflow runs](https://github.com/abhishek-balsure/phishing-detector-pro/actions)

## Features

### Core Security
- **ML-Powered Detection**: Random Forest model (selected over XGBoost via 5-fold cross-validation) trained on 1,964 labeled URLs — 88% test accuracy, 90.5% CV accuracy, 94.9% AUC-ROC. Full metrics in `model_metrics.json` / `confusion_matrix.png`.
- **Multi-Format Analysis**: URL, email, QR code, message, and social media link scanning
- **Batch Processing**: Scan multiple URLs simultaneously
- **Real-Time Scanning**: Instant threat detection and classification

### User Experience
- **OAuth Authentication**: Seamless login with Google and GitHub
- **Dark/Light Mode**: Professional UI with full dark mode support
- **Responsive Design**: Works seamlessly across all devices
- **Toast Notifications**: Real-time feedback for user actions

### Account Management
- User accounts with secure password hashing
- Personal dashboard with scan statistics
- Bookmark favorite URLs for monitoring
- Full scan history with search and filtering
- Profile management

### Security Features
- Account lockout after failed login attempts (5 attempts = 15 min lockout)
- Password strength validation
- JWT-secured REST API
- Redis-backed rate limiting
- PostgreSQL with parameterized queries (SQL injection prevention)

### Enterprise
- [Terms of Service](http://35.154.32.25:5000/terms)
- [Privacy Policy](http://35.154.32.25:5000/privacy)
- Professional legal pages
- Docker-based deployment
- CI/CD with GitHub Actions

## Tech Stack

| Category | Technologies |
|---|---|
| Backend | Python 3.11, Flask 3.0, Gunicorn |
| Machine Learning | scikit-learn, XGBoost, NumPy, pandas, SHAP |
| Database | PostgreSQL 15 |
| Cache / Rate Limiting | Redis 7, Flask-Limiter |
| Authentication | Flask sessions, JWT (Flask-JWT-Extended), OAuth (Flask-Dance) |
| Frontend | HTML5, Bootstrap 5, JavaScript, Plus Jakarta Sans fonts |
| Containerization | Docker, Docker Compose |
| CI/CD | GitHub Actions, Docker Hub |
| Hosting | AWS EC2 |

## Architecture

```mermaid
flowchart LR
    Dev[Developer Push] --> GH[GitHub Repository]
    GH --> CI[GitHub Actions]
    CI --> Stage1[Stage 1: Build and dependency checks]
    CI --> Stage2[Stage 2: Docker build and push]
    CI --> Stage3[Stage 3: EC2 deploy via SSH]
    Stage2 --> DH[Docker Hub image]
    DH --> EC2[AWS EC2 host]
    Stage3 --> EC2

    subgraph EC2 Docker Compose Stack
        Web[Flask + Gunicorn container]
        DB[PostgreSQL container]
        Redis[Redis container]
        Web --> DB
        Web --> Redis
    end

    User[Browser or API client] --> EC2
    EC2 --> Web
```

## Project Structure

```text
phishing-detector-pro/
|-- app.py                     # Main Flask application
|-- feature_extraction.py       # ML feature extraction
|-- phishing_model.pkl          # Trained ML model
|-- requirements.txt            # Python dependencies
|-- Dockerfile                  # Docker image
|-- docker-compose.yml          # Container orchestration
|-- .env                       # Environment variables
|-- .env.ec2                   # EC2 deployment config
|-- .github/
|   `-- workflows/
|       `-- deploy.yml          # CI/CD pipeline
|-- templates/                  # Jinja2 templates
|   |-- base.html               # Base template
|   |-- login.html              # Login page
|   |-- signup.html             # Registration page
|   |-- dashboard.html          # User dashboard
|   |-- bookmarks.html          # Saved URLs
|   |-- history.html            # Scan history
|   |-- admin.html              # Admin panel
|   |-- terms.html              # Terms of Service
|   |-- privacy.html            # Privacy Policy
|   |-- check_url.html          # URL scanner
|   |-- email_scanner.html      # Email scanner
|   |-- qr_scanner.html         # QR code scanner
|   |-- social_scanner.html     # Social media scanner
|   |-- batch_check.html        # Batch URL checker
|   |-- profile.html            # User profile
|   |-- forgot_password.html     # Password recovery
|   |-- reset_password.html     # Password reset
|   |-- help.html               # Help center
|   |-- about.html              # About page
|   `-- index.html              # Landing page
|-- static/
|   |-- css/
|   |   |-- style.css           # Main styles
|   |   |-- animations.css      # Animations
|   |   `-- (other assets)
|   `-- js/
|       `-- (JavaScript files)
```

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker (optional)

### Run Locally

```bash
git clone https://github.com/abhishek-balsure/phishing-detector-pro.git
cd phishing-detector-pro

python -m venv venv
# Windows PowerShell: .\venv\Scripts\Activate.ps1
# Linux/Mac: source venv/bin/activate

pip install -r requirements.txt

# Configure environment
cp .env.example .env  # Edit .env with your database credentials

python app.py
```

Open `http://localhost:5000`

### Run with Docker

```bash
git clone https://github.com/abhishek-balsure/phishing-detector-pro.git
cd phishing-detector-pro

docker-compose up --build -d
```

Open `http://localhost:5000` or `http://35.154.32.25:5000`

## Docker Deployment

The Compose stack includes:

- `web` - Flask app served by Gunicorn
- `db` - PostgreSQL 15
- `redis` - Redis 7 for rate-limit storage

### Docker Commands

```bash
# Start stack
docker-compose up --build -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f web

# Stop stack
docker-compose down

# Rebuild after changes
docker-compose up --build -d

# Clean up unused images
docker image prune -f
```

## Environment Variables

Configure in `.env`:

```env
SECRET_KEY=your-flask-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
REDIS_URL=redis://localhost:6379/0
POSTGRES_DB=dbname
POSTGRES_USER=user
POSTGRES_PASSWORD=password
FLASK_ENV=production

# OAuth (optional - for Google/GitHub login)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### OAuth Setup

**Google OAuth:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID
3. Add authorized redirect: `http://your-domain/auth/google/callback`
4. Add credentials to `.env`

**GitHub OAuth:**
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create New OAuth App
3. Add callback URL: `http://your-domain/auth/github/callback`
4. Add credentials to `.env`

## AWS EC2 Deployment

### Manual Setup

1. Launch Ubuntu EC2 instance
2. Open security group:
   - `22` for SSH
   - `5000` for application

3. Install Docker:
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

4. Deploy:
```bash
git clone https://github.com/abhishek-balsure/phishing-detector-pro.git
cd phishing-detector-pro
docker-compose up -d
```

### Update Deployment

```bash
cd ~/phishing-detector-pro
git pull
docker-compose pull
docker-compose up -d --build
docker image prune -f
```

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/deploy.yml`) runs:

1. **Build & Test** - Dependency validation
2. **Docker Build** - Build and push to Docker Hub
3. **EC2 Deploy** - SSH and restart containers

### Required GitHub Secrets

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `EC2_HOST`
- `EC2_SSH_KEY`

## API Documentation

### Authentication

```
POST /api/register     - Create account
POST /api/login        - Login
POST /api/forgot_password - Request password reset
```

JWT tokens expire after 24 hours. Include in requests:

```http
Authorization: Bearer <token>
```

### Rate Limits

- Global: 100 requests/hour per IP
- Login: 5 requests/minute per IP
- API: 20 requests/minute per user
- Exceeded limits return 429 with Retry-After header

### Endpoints

#### Register
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user","email":"user@example.com","password":"StrongPass1","confirm_password":"StrongPass1"}'
```

#### Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"StrongPass1"}'
```

#### Scan URL
```bash
curl -X POST http://localhost:5000/api/check_url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url":"https://example.com"}'
```

#### Batch Scan
```bash
curl -X POST http://localhost:5000/api/batch_check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"urls":["https://example.com","https://test.com"]}'
```

#### Statistics
```bash
curl http://localhost:5000/api/stats \
  -H "Authorization: Bearer <token>"
```

## Security

- Passwords hashed with Werkzeug
- JWT for API authentication
- Parameterized SQL queries
- Rate limiting on all endpoints
- Account lockout protection
- OAuth 2.0 for social login
- CSRF protection via Flask-WTF

## Legal

- [Terms of Service](http://35.154.32.25:5000/terms)
- [Privacy Policy](http://35.154.32.25:5000/privacy)

## License

MIT License - see LICENSE file for details.

## Support

- Help Center: `/help`
- Create GitHub Issue
- Email: support@shieldguard-pro.com
