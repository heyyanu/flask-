# Flask Email Verification Application - Setup Guide

## Quick Start

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd "python week8"
   ```

2. **Set up configuration**
   ```bash
   cp .config.example .config
   ```
   Then edit `.config` with your actual credentials:
   - Add your Gmail address
   - Add your Gmail app password ([How to get app password](https://support.google.com/accounts/answer/185833))
   - Set a strong SECRET_KEY

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

## Features
- User registration with email verification
- Secure password hashing with bcrypt
- CSRF protection
- Email verification with 6-digit codes
- Login/logout functionality

## Security Notes
- Never commit the `.config` file - it contains sensitive credentials
- The `.config.example` file shows what variables are needed
- All passwords are hashed using bcrypt
- CSRF tokens protect all forms

## Email Configuration
This app uses Gmail SMTP. To use your own email:
1. Enable 2-factor authentication on your Google account
2. Generate an app-specific password
3. Add credentials to `.config` file
