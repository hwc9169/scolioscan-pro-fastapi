import fastapi
import google_auth_oauthlib.flow
import requests
import jwt
import datetime
import os

from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import RedirectResponse, Response

app = fastapi.FastAPI()

ORIGINS = [
    "http://localhost:5173",
    "https://localhost:5173",
    "https://accounts.google.com",
]
REDIRECT_URI = "https://localhost:8000/oauth2callback"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key-change-this-in-production")
JWT_ALGORITHM = "HS256"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]


@app.get("/authorize")
def authorize(request: Request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES
    )

    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent')    

    return RedirectResponse(authorization_url)

@app.get("/oauth2callback")
def oauth2callback(state: str, code: str):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES,
        state=state
    )
    flow.redirect_uri = REDIRECT_URI
    flow.fetch_token(code=code)

    credentials = flow.credentials
    
    # Use the Google token to get user information
    headers = {'Authorization': f'Bearer {credentials.token}'}
    user_info_response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
    user_info = user_info_response.json()
    
    user_email = user_info.get('email')
    user_name = user_info.get('name', '')
    
    if not user_email:
        return Response(content="Failed to get user email", status_code=400)
    
    # Generate JWT token with user email
    payload = {
        'email': user_email,
        'name': user_name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),  # Token expires in 24 hours
        'iat': datetime.datetime.utcnow()
    }
    
    access_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    # Create response with access_token cookie
    response = Response(content="Authentication successful")
    
    # Set JWT token as HTTP-only cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400  # 24 hours
    )

    return response


def decode_jwt_token(token: str):
    """Helper function to decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.get("/user")
def get_current_user(request: Request):
    """Get current user from JWT token in cookie"""
    access_token = request.cookies.get("access_token")
    
    if not access_token:
        return Response(content="No authentication token found", status_code=401)
    
    payload = decode_jwt_token(access_token)


if __name__ == "__main__":
    fastapi.run(app)
