# AWS to OCI Policy Translator

A web application that translates AWS IAM policies to Oracle Cloud Infrastructure (OCI) policies with support for various service-specific policy types.

## Features

- Simple policy translation for general AWS to OCI policy conversion
- Advanced service-specific policy translation:
  - IAM policies
  - Compute policies
  - Object Storage policies
- Comprehensive OCI policy reference documentation
- Policy validation to ensure correct syntax
- Save policies as text files
- Up-to-date service mappings between AWS and OCI
- Web scraper to keep OCI policy reference information current

## Prerequisites for Ubuntu

- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for cloning the repository)

## Installation on Ubuntu

### Automatic Installation

The easiest way to install and run the application is by using the provided installation script:

```bash
# Make the script executable
chmod +x install_ubuntu.sh

# Run the installation script
./install_ubuntu.sh
```

This script will:
1. Update your system packages
2. Install Python, pip, and required dependencies
3. Create a virtual environment
4. Install required Python packages
5. Set up and run the application

### Manual Installation

If you prefer to install the application manually, follow these steps:

1. Update your system packages:
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. Install Python, pip, and other dependencies:
   ```bash
   sudo apt install -y python3 python3-pip python3-venv
   ```

3. Clone the repository (if you haven't already):
   ```bash
   git clone https://github.com/your-repo/aws2ocipolicy.git
   cd aws2ocipolicy
   ```

4. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

5. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

   If the requirements.txt file doesn't exist, install the necessary packages:
   ```bash
   pip install flask requests beautifulsoup4
   ```

6. Run the application:
   ```bash
   python app.py
   ```

## Running the Application

After installation, the application will be available at:
```
http://localhost:5001
```

To run the application in production, you should use a WSGI server like Gunicorn:

```bash
# Install Gunicorn (if not already installed)
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 app:app
```

## Using the Application

1. **Simple Policy Translation**:
   - Navigate to the "Simple Policy" page
   - Enter your AWS IAM policy in JSON format
   - Specify the OCI group name
   - Click "Translate Policy"
   - Review the generated OCI policy
   - Use the "Save Policy" button to download the policy as a text file

2. **Advanced Policy Translation**:
   - Select the appropriate service type from the Advanced Policy dropdown menu
   - Enter your AWS service-specific policy
   - Configure the required OCI parameters
   - Click "Translate Policy"
   - Review and save the generated policy

3. **OCI Reference Policies**:
   - Navigate to the "OCI Reference Policies" page to browse comprehensive policy documentation
   - Use the tabs to navigate between different service categories
   - Expand sections to view details about resource types, verbs, and API operations
   - Click "Update Policy Reference Data" to refresh the data from OCI documentation

## Troubleshooting

- If you encounter any dependency issues, ensure that all required packages are installed:
  ```bash
  pip install flask requests beautifulsoup4
  ```

- If the policy reference parser fails, check your internet connection and try again. The parser needs to access OCI documentation online.

- For any issues with the application, check the console output for error messages.

## License

[License details would go here]
