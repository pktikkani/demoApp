import base64
import hashlib
import json
import urllib
import urllib.parse
from flask import Flask, request, redirect, session, url_for, render_template_string
import requests
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Your Canva API credentials (store these securely in production)
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTH_URL = "https://www.canva.com/api/oauth/authorize"
TOKEN_URL = "https://api.canva.com/oauth/token"

# Define the scopes your app needs
SCOPES = "app:read app:write design:content:read design:meta:read design:content:write design:permission:read design:permission:write folder:read folder:write folder:permission:read folder:permission:write asset:read asset:write comment:read comment:write brandtemplate:meta:read brandtemplate:content:read profile:read"


# PKCE helper functions
def generate_code_verifier():
    """Generate a code_verifier as per the PKCE spec."""
    return secrets.token_urlsafe(96)[:128]


def generate_code_challenge(verifier):
    """Generate a code_challenge as per the PKCE spec."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@app.route('/')
def index():
    return '''
        <h1>Canva API Integration Demo</h1>
        <p>This app demonstrates OAuth 2.0 with PKCE for Canva API integration.</p>
        <a href="/login" style="padding: 10px 20px; background-color: #00C4CC; color: white; text-decoration: none; border-radius: 4px;">Connect with Canva</a>
    '''


@app.route('/login')
def login():
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['state'] = state

    # Generate PKCE code_verifier and code_challenge
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Store code_verifier in session for later use
    session['code_verifier'] = code_verifier

    # Log for debugging
    print(f"Generated code_verifier: {code_verifier}")
    print(f"Generated code_challenge: {code_challenge}")
    print(f"Generated state: {state}")

    # Build the authorization URL
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPES,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'  # Must be uppercase 'S256'
    }

    auth_uri = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    print(f"Auth URL: {auth_uri}")

    return redirect(auth_uri)


@app.route('/callback')
def callback():
    # Check for errors first
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    if error:
        return f"Authorization error: {error} - {error_description}", 400

    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "No authorization code received", 400

    # Validate state to prevent CSRF
    received_state = request.args.get('state')
    stored_state = session.get('state')
    if not received_state or received_state != stored_state:
        return "State verification failed. Possible CSRF attack", 403

    # Get stored code_verifier
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return "Code verifier not found in session", 400

    # Exchange code for access token
    token_response = exchange_code_for_token(code, code_verifier)

    return render_template_string('''
        <h1>Authentication {{result}}</h1>
        <p>{{message}}</p>
        <pre>{{details}}</pre>
        <a href="/">Back to Home</a>
    ''', result=token_response.get('result'),
                                  message=token_response.get('message'),
                                  details=token_response.get('details', ''))


def exchange_code_for_token(code, code_verifier):
    """Exchange authorization code for access token"""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        print(f"Sending token request with: code={code}, code_verifier={code_verifier[:10]}...")
        response = requests.post(TOKEN_URL, headers=headers, data=data)

        print(f"Token response status: {response.status_code}")
        print(f"Token response headers: {dict(response.headers)}")
        print(f"Token response body: {response.text[:100]}...")

        if response.status_code == 200:
            try:
                token_info = response.json()
                access_token = token_info.get('access_token')
                refresh_token = token_info.get('refresh_token')

                # Store tokens securely in a real app
                # For demo purposes, we just display a success message
                return {
                    'result': 'Successful',
                    'message': 'Your app is now connected to Canva!',
                    'details': json.dumps(token_info, indent=2)
                }
            except json.JSONDecodeError as e:
                return {
                    'result': 'Failed',
                    'message': f'Failed to parse token response: {str(e)}',
                    'details': response.text
                }
        else:
            return {
                'result': 'Failed',
                'message': f'Error obtaining access token (HTTP {response.status_code})',
                'details': response.text
            }
    except Exception as e:
        return {
            'result': 'Failed',
            'message': f'Exception during token exchange: {str(e)}',
            'details': ''
        }


# API request example (once you have a token)
def make_api_request(endpoint, access_token):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(f"https://api.canva.com/v1/{endpoint}", headers=headers)
    return response.json()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)