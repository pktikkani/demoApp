import base64
import hashlib
import urllib
import urllib.parse
from flask import Flask, request, redirect, session, url_for
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


# Functions for PKCE
def generate_code_verifier():
    return secrets.token_urlsafe(64)[:128]


def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@app.route('/')
def index():
    return '''
        <h1>Canva API Integration Demo</h1>
        <a href="/login">Connect with Canva</a>
    '''


@app.route('/login')
def login():
    # Generate code verifier and challenge for PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # Store code_verifier in session for later use
    session['code_verifier'] = code_verifier

    # Set up authorization parameters
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': 'app:read app:write design:content:read design:meta:read design:content:write design:permission:read design:permission:write folder:read folder:write folder:permission:read folder:permission:write asset:read asset:write comment:read comment:write brandtemplate:meta:read brandtemplate:content:read profile:read',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'  # Must be uppercase 'S256'
    }

    # Generate and redirect to authorization URL
    auth_uri = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    print(f"Auth URL: {auth_uri}")
    return redirect(auth_uri)


@app.route('/callback')
def callback():
    # Check for error
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    if error:
        return f"Authorization error: {error} - {error_description}", 400

    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "No authorization code received", 400

    # Get stored code_verifier
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return "Code verifier not found in session", 400

    # Exchange code for access token using PKCE
    auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {auth_header}'
    }

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }

    try:
        response = requests.post(TOKEN_URL, headers=headers, data=data)
        print(f"Token response status: {response.status_code}")
        print(f"Token response body: {response.text}")

        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get('access_token')
            refresh_token = token_info.get('refresh_token')

            # For demonstration - in a real app, store these securely
            return f'''
                <h1>Authentication Successful!</h1>
                <p>Your app is now connected to Canva.</p>
                <p>Access token: {access_token[:10]}...</p>
                <p>Refresh token: {refresh_token[:10] if refresh_token else 'None'}...</p>
            '''
        else:
            return f"Error obtaining access token: {response.text}", 400
    except Exception as e:
        return f"Exception during token exchange: {str(e)}", 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)