#!/bin/bash

# SecureCMS Deployment Script for PythonAnywhere
# This script automates the deployment process with security checks

set -e  # Exit on error

echo "==================================="
echo "SecureCMS PythonAnywhere Deployment"
echo "==================================="

# Configuration
PROJECT_NAME="securecms"
PYTHON_VERSION="3.10"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if we're on PythonAnywhere
if [[ ! -f /bin/pa_autoconfigure_django.py ]]; then
    print_warning "This script is optimized for PythonAnywhere. Continuing anyway..."
fi

# Step 1: Create virtual environment
print_status "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python${PYTHON_VERSION} -m venv venv
else
    print_warning "Virtual environment already exists"
fi

# Step 2: Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Step 3: Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Step 4: Install requirements
print_status "Installing requirements..."
pip install -r requirements.txt

# Step 5: Check for .env file
if [ ! -f ".env" ]; then
    print_error ".env file not found! Please create it from .env.example"
    echo "cp .env.example .env"
    echo "Then edit .env with your configuration"
    exit 1
fi

# Step 6: Generate SECRET_KEY if not set
print_status "Checking SECRET_KEY..."
if grep -q "your-secret-key-here" .env; then
    print_warning "Generating new SECRET_KEY..."
    NEW_SECRET_KEY=$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
    sed -i "s/your-secret-key-here-minimum-50-chars-replace-in-production/${NEW_SECRET_KEY}/" .env
    print_status "New SECRET_KEY generated and saved"
fi

# Step 7: Create necessary directories
print_status "Creating required directories..."
mkdir -p static media logs templates/cms templates/accounts templates/api apps/accounts apps/cms apps/api

# Step 8: Run security checks
print_status "Running security checks..."
echo "Running Bandit security scan..."
bandit -r . -f json -o security_report.json --severity-level medium || true

echo "Checking for vulnerable dependencies..."
safety check --json || print_warning "Some vulnerabilities found - review and update packages"

# Step 9: Collect static files
print_status "Collecting static files..."
python manage.py collectstatic --noinput

# Step 10: Run migrations
print_status "Running database migrations..."
python manage.py makemigrations accounts cms api --noinput || true
python manage.py migrate --noinput

# Step 11: Create superuser (if doesn't exist)
print_status "Checking for superuser..."
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    print('No superuser found. Please create one:')
    exit(1)
" || {
    print_warning "Creating superuser..."
    python manage.py createsuperuser
}

# Step 12: Run tests
print_status "Running tests..."
python manage.py test --verbosity=2 || print_warning "Some tests failed - review before deploying"

# Step 13: Check Django deployment settings
print_status "Checking deployment configuration..."
python manage.py check --deploy || print_warning "Some deployment checks failed - review warnings"

# Step 14: Set file permissions
print_status "Setting secure file permissions..."
chmod 755 .
chmod 644 *.py
chmod 755 manage.py
chmod 600 .env
chmod 755 static media
chmod 644 db.sqlite3 2>/dev/null || true

# Step 15: Create WSGI configuration for PythonAnywhere
print_status "Creating PythonAnywhere WSGI configuration..."
cat > /var/www/${USER}_pythonanywhere_com_wsgi.py << EOF
import sys
import os
from pathlib import Path

# Add your project directory to the sys.path
project_home = '/home/${USER}/${PROJECT_NAME}'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variable to tell django where your settings.py is
os.environ['DJANGO_SETTINGS_MODULE'] = 'securecms.settings'

# Load environment variables from .env file
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
EOF 2>/dev/null || print_warning "Could not create WSGI file - create manually on PythonAnywhere"

# Step 16: Pre-commit hooks setup
print_status "Setting up pre-commit hooks..."
pre-commit install || print_warning "Pre-commit not installed"

# Step 17: Final security reminders
echo ""
echo "==================================="
echo "DEPLOYMENT CHECKLIST"
echo "==================================="
echo ""
echo "Please verify the following before going live:"
echo ""
echo "[ ] Set DEBUG=False in .env"
echo "[ ] Configure proper ALLOWED_HOSTS in .env"
echo "[ ] Set up proper database (MySQL/PostgreSQL) instead of SQLite"
echo "[ ] Configure email settings for password reset"
echo "[ ] Set up Cloudflare Turnstile keys for bot protection"
echo "[ ] Configure Sentry for error tracking"
echo "[ ] Enable HTTPS (automatic on PythonAnywhere)"
echo "[ ] Review security_report.json for any issues"
echo "[ ] Set up regular backups"
echo "[ ] Configure log rotation"
echo "[ ] Test 2FA setup with Google Authenticator"
echo ""
echo "==================================="
echo -e "${GREEN}Deployment preparation complete!${NC}"
echo "==================================="
echo ""
echo "Next steps for PythonAnywhere:"
echo "1. Go to Web tab in PythonAnywhere dashboard"
echo "2. Set Python version to ${PYTHON_VERSION}"
echo "3. Set source code directory to: /home/${USER}/${PROJECT_NAME}"
echo "4. Set working directory to: /home/${USER}/${PROJECT_NAME}"
echo "5. Set virtualenv to: /home/${USER}/${PROJECT_NAME}/venv"
echo "6. Edit WSGI configuration file with the generated content"
echo "7. Set static files mapping:"
echo "   URL: /static/ -> Directory: /home/${USER}/${PROJECT_NAME}/static"
echo "   URL: /media/ -> Directory: /home/${USER}/${PROJECT_NAME}/media"
echo "8. Reload the web app"
echo ""
print_status "Script completed successfully!"