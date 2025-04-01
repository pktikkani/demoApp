from flask import Flask, request, redirect, session, url_for
import requests
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Your Canva API credentials (store these securely in production)
CLIENT_ID = ""
CLIENT_SECRET = ""
REDIRECT_URI = ""  # Must match what you register in Canva


@app.route('/')
def index():
    return '''
        <h1>Canva API Integration Demo</h1>
        <a href="/login">Connect with Canva</a>
    '''


@app.route('/login')
def login():
    # Generate authorization URL
    auth_url = "https://www.canva.com/oauth/authorize"
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "designs:read",  # Adjust scopes as needed
        "state": secrets.token_hex(16)  # Prevent CSRF
    }

    # Store state for verification
    session['oauth_state'] = params['state']

    # Redirect to Canva's authorization page
    auth_uri = f"{auth_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return redirect(auth_uri)


@app.route('/callback')
def callback():
    # Verify state parameter to prevent CSRF
    if request.args.get('state') != session.get('oauth_state'):
        return "State verification failed", 403

    # Exchange authorization code for access token
    code = request.args.get('code')
    token_url = "https://www.canva.com/oauth/token"

    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    response = requests.post(token_url, data=token_data)

    if response.status_code == 200:
        token_info = response.json()

        # Store tokens securely (in a real app)
        access_token = token_info.get("access_token")

        # Now you can use this token to make API calls
        return f'''
            <h1>Authentication Successful!</h1>
            <p>Your app is now connected to Canva.</p>
        '''
    else:
        return f"Error obtaining access token: {response.text}", 400


if __name__ == '__main__':
    app.run(debug=True, port=5000)