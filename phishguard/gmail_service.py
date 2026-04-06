from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os
import base64

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service():
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # Check if credentials exist and are valid
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            from google.auth.transport.requests import Request
            try:
                creds.refresh(Request())
                # Save refreshed credentials
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                print(f"❌ Failed to refresh token: {e}")
                raise Exception("Authentication expired. Please log in again.")
        else:
            raise Exception("No valid credentials found. Please log in.")

    service = build('gmail', 'v1', credentials=creds)
    return service

def _decode_body(data: str) -> str:
    """Decode base64 URL-safe encoded email body"""
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace")
    except Exception:
        return ""

def extract_message_body(message: dict) -> str:
    """Extract text body from Gmail message payload"""
    payload = message.get("payload", {})
    
    # Try direct body first
    body = payload.get("body", {})
    if body.get("data"):
        return _decode_body(body["data"])
    
    # Check parts for text/plain or text/html
    parts = payload.get("parts", [])
    for part in parts:
        mime = part.get("mimeType", "")
        if mime in ("text/plain", "text/html"):
            data = part.get("body", {}).get("data")
            if data:
                return _decode_body(data)
        
        # Check nested parts (multipart messages)
        if "parts" in part:
            for subpart in part["parts"]:
                if subpart.get("mimeType") in ("text/plain", "text/html"):
                    data = subpart.get("body", {}).get("data")
                    if data:
                        return _decode_body(data)
    
    return ""

def get_message_body(service, user_id: str, msg_id: str) -> str:
    """Fetch and extract body text from a specific message"""
    try:
        msg = service.users().messages().get(userId=user_id, id=msg_id, format="full").execute()
        return extract_message_body(msg)
    except Exception:
        return ""

def get_user_profile(service):
    """Get user profile information including email and message stats"""
    try:
        profile = service.users().getProfile(userId='me').execute()
        return {
            'email': profile.get('emailAddress', 'N/A'),
            'total_messages': profile.get('messagesTotal', 0),
            'total_threads': profile.get('threadsTotal', 0),
            'history_id': profile.get('historyId', 'N/A')
        }
    except Exception as e:
        return {
            'email': 'N/A',
            'total_messages': 0,
            'total_threads': 0,
            'history_id': 'N/A'
        }
