#!/bin/bash

# AWS to OCI Policy Translator Installation Script for Ubuntu
# This script installs all prerequisites and sets up the application

# Exit on any error
set -e

echo "====================================================="
echo "  AWS to OCI Policy Translator Installation Script"
echo "====================================================="
echo ""

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Step 1: Updating system packages..."
sudo apt update
sudo apt upgrade -y

echo "Step 2: Installing Python and dependencies..."
sudo apt install -y python3 python3-pip python3-venv git

echo "Step 3: Creating Python virtual environment..."
# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

echo "Step 4: Installing Python packages..."
# Check if requirements.txt exists
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    # Install required packages
    pip install flask requests beautifulsoup4
    
    # Create requirements.txt for future use
    pip freeze > requirements.txt
    echo "Created requirements.txt with installed packages"
fi

# Create static/data directory if it doesn't exist
echo "Step 5: Setting up directory structure..."
mkdir -p static/data

echo "Step 6: Setting up application..."
# If not running in a server environment, use development mode
export FLASK_APP=app.py
export FLASK_ENV=development

echo "====================================================="
echo "  Installation Complete!"
echo "====================================================="
echo ""
echo "To run the application:"
echo "1. Make sure you're in the application directory"
echo "2. Activate the virtual environment: source venv/bin/activate"
echo "3. Run: python app.py"
echo ""
echo "The application will be available at: http://localhost:5001"
echo ""
echo "Or, for production environments, use Gunicorn:"
echo "pip install gunicorn"
echo "gunicorn -w 4 -b 0.0.0.0:5001 app:app"
echo "====================================================="

# Ask if the user wants to run the application now
read -p "Do you want to run the application now? (y/n): " RUN_NOW
if [[ $RUN_NOW == "y" || $RUN_NOW == "Y" ]]; then
    echo "Starting the application..."
    python app.py
else
    echo "You can run the application later using the instructions above."
fi
