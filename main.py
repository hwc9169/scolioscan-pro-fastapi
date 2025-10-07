import fastapi
import google_auth_oauthlib.flow
from starlette.middleware.sessions import SessionMiddleware
import requests
import jwt
import datetime
import os

from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi import Request
from fastapi.responses import RedirectResponse, Response

app = fastapi.FastAPI()


load_dotenv()

# Get environment variables
OAUTH2_CLIENT_SECRET_FILE = os.getenv("OAUTH2_CLIENT_SECRET_FILE")
REDIRECT_URI = os.getenv("REDIRECT_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
assert OAUTH2_CLIENT_SECRET_FILE is not None
assert REDIRECT_URI is not None
assert JWT_SECRET_KEY is not None

JWT_ALGORITHM = "HS256"
ORIGINS = [
    "http://localhost:5173",
    "https://localhost:5173",
    "https://accounts.google.com",
]
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/authorize")
def authorize(request: Request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        OAUTH2_CLIENT_SECRET_FILE,
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
        OAUTH2_CLIENT_SECRET_FILE,
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
    jwt_token = request.cookies.get("jwt_token")
    
    if not jwt_token:
        return Response(content="No authentication token found", status_code=401)
    
    payload = decode_jwt_token(jwt_token)
    
    if not payload:
        return Response(content="Invalid or expired token", status_code=401)
    
    return {
        "email": payload.get("email"),
        "name": payload.get("name"),
        "expires_at": datetime.datetime.fromtimestamp(payload.get("exp"))
    }


if __name__ == "__main__":
    fastapi.run(app)
