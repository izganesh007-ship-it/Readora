# Readora - Netflix-Style eBook Store

A premium, minimalist eBook marketplace with Netflix-inspired dark UI, Bitcoin payments, and secure admin panel.

## Features

- **Netflix-Style UI**: Black + red premium theme with horizontal scrolling rows
- **Free & Paid eBooks**: Flexible pricing with online reader for free books
- **Bitcoin Payments**: Blockonomics integration for crypto payments
- **One-Time Downloads**: Expiring, single-use download links for purchased books
- **Cookie-Based Wishlist**: No login required to save favorites
- **Secure Admin Panel**: Hidden URL, brute-force protection, IP lockouts
- **Dynamic Categories**: Add/remove categories via admin panel
- **Responsive Design**: Works on desktop, tablet, and mobile

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. **Initialize database**:
   ```bash
   flask init-db
   ```

4. **Run the app**:
   ```bash
   python app.py
   ```

5. **Access admin panel**:
   - URL: `http://localhost:5000/readora-admin`
   - Use credentials from your `.env` file

## Admin Panel Security

- Hidden at `/readora-admin` (not linked anywhere on the site)
- 3 failed login attempts = 30-minute IP lockout
- Rate limiting on login endpoint
- Session-based authentication with Flask-Login

## Deployment Guide

See `DEPLOYMENT.md` for full instructions on deploying to production.
