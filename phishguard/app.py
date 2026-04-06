from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from google_auth_oauthlib.flow import Flow
from gmail_service import get_gmail_service, get_message_body, get_user_profile
from risk_engine import calculate_risk
from googleapiclient.discovery import build
import os
import json
import re
from collections import defaultdict

# MANDATORY: Allow OAuth over HTTP for localhost
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Community intelligence: Store scam reports
scam_reports = defaultdict(int)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

@app.get("/")
def home():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShieldX - Email Security</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
                margin: 0;
                padding: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                text-align: center;
                background: linear-gradient(to bottom, #ffffff 0%, #f8f9fa 100%);
                padding: 60px 80px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.4);
                max-width: 650px;
                border: 1px solid rgba(255,255,255,0.2);
            }
            h1 {
                font-size: 48px;
                margin: 0;
                background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .tagline {
                color: #64748b;
                font-size: 18px;
                margin: 15px 0 40px 0;
                font-weight: 500;
            }
            .features {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin: 40px 0;
                text-align: left;
            }
            .feature {
                padding: 20px;
                background: white;
                border-radius: 12px;
                border: 2px solid #e2e8f0;
                transition: all 0.3s ease;
            }
            .feature:hover {
                border-color: #06b6d4;
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(6, 182, 212, 0.2);
            }
            .feature h3 {
                margin: 0 0 8px 0;
                font-size: 18px;
                color: #0891b2;
                font-weight: 600;
            }
            .feature p {
                color: #475569;
                margin: 0;
                font-size: 14px;
            }
            .btn {
                display: inline-block;
                padding: 18px 50px;
                background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
                color: white;
                text-decoration: none;
                border-radius: 50px;
                font-size: 18px;
                font-weight: bold;
                transition: all 0.3s ease;
                box-shadow: 0 8px 25px rgba(6, 182, 212, 0.3);
            }
            .btn:hover {
                transform: translateY(-3px);
                box-shadow: 0 12px 35px rgba(6, 182, 212, 0.5);
                background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%);
            }
            .privacy-note {
                margin-top: 30px;
                color: #94a3b8;
                font-size: 13px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>&#x1F6E1;&#xFE0F; ShieldX</h1>
            <p class="tagline">AI-Powered Phishing Detection for Your Gmail</p>
            
            <div class="features">
                <div class="feature">
                    <h3>&#x1F50D; Smart Detection</h3>
                    <p>Advanced algorithms identify phishing patterns</p>
                </div>
                <div class="feature">
                    <h3>&#x26A1; Real-time Analysis</h3>
                    <p>Instant risk scoring for every email</p>
                </div>
                <div class="feature">
                    <h3>&#x1F3AF; Risk Scoring</h3>
                    <p>Clear verdicts: Safe, Suspicious, High Risk</p>
                </div>
                <div class="feature">
                    <h3>&#x1F6E1; Stay Protected</h3>
                    <p>Catch phishing attempts before you do</p>
                </div>
            </div>
            
            <a href="/login" class="btn">Connect Gmail & Analyze</a>
            
            <p class="privacy-note">
                Your privacy matters. We only read email metadata for analysis.
            </p>
        </div>
    </body>
    </html>
    """)

@app.get("/login")
def login():
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        redirect_uri='http://localhost:8000/auth/callback'
    )

    auth_url, _ = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def auth_callback(request: Request):
    try:
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri='http://localhost:8000/auth/callback'
        )

        flow.fetch_token(authorization_response=str(request.url))
        creds = flow.credentials

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

        return RedirectResponse("/inbox")

    except Exception as e:
        return {"error": str(e)}

@app.get("/logout")
def logout():
    """Logout user by removing token file and redirecting to home"""
    import os
    if os.path.exists('token.json'):
        os.remove('token.json')
    return RedirectResponse("/")

@app.get("/profile")
def profile(request: Request):
    """User profile page"""
    try:
        service = get_gmail_service()
        profile = service.users().getProfile(userId='me').execute()
        
        return templates.TemplateResponse("profile.html", {
            "request": request,
            "email": profile.get('emailAddress', 'N/A'),
            "total_messages": profile.get('messagesTotal', 0),
            "threads_total": profile.get('threadsTotal', 0)
        })
    except:
        return RedirectResponse("/login")

@app.get("/settings")
def settings(request: Request):
    """Settings page"""
    try:
        # Verify user is logged in
        get_gmail_service()
        return templates.TemplateResponse("settings.html", {
            "request": request
        })
    except:
        return RedirectResponse("/login")

@app.get("/reports")
def reports(request: Request):
    """User reports page"""
    try:
        # Verify user is logged in
        get_gmail_service()
        
        # Get reports from scam_reports
        from datetime import datetime, timedelta
        report_list = []
        for domain, count in sorted(scam_reports.items(), key=lambda x: x[1], reverse=True):
            report_list.append({
                "domain": domain,
                "date": (datetime.now() - timedelta(days=len(report_list))).strftime("%b %d, %Y"),
                "count": count,
                "status": "reviewed" if count > 2 else "pending"
            })
        
        reviewed = sum(1 for r in report_list if r['status'] == 'reviewed')
        pending = sum(1 for r in report_list if r['status'] == 'pending')
        
        return templates.TemplateResponse("reports.html", {
            "request": request,
            "reports": report_list,
            "total_reports": len(report_list),
            "reviewed_reports": reviewed,
            "pending_reports": pending
        })
    except:
        return RedirectResponse("/login")

@app.get("/inbox")
def inbox(request: Request):
    try:
        service = get_gmail_service()
        
        # Get user profile information
        user_profile = get_user_profile(service)
        
        print(f"✓ Gmail service connected. User: {user_profile.get('email', 'Unknown')}")
        
        results = service.users().messages().list(
            userId='me',
            maxResults=20
        ).execute()
        
        print(f"✓ Retrieved {len(results.get('messages', []))} messages")

        messages = results.get('messages', [])
        email_list = []

        for msg in messages:
            try:
                data = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata'
                ).execute()

                headers = data['payload']['headers']
                sender = subject = ""

                for h in headers:
                    if h['name'] == 'From':
                        sender = h['value']
                    if h['name'] == 'Subject':
                        subject = h['value']

                # Get full email body for analysis (with fallback to snippet)
                snippet = data.get("snippet", "")
                try:
                    email_body = get_message_body(service, 'me', msg['id'])
                    content_for_analysis = email_body if email_body else snippet
                except:
                    content_for_analysis = snippet
                
                # Calculate risk using full body or snippet
                risk_analysis = calculate_risk(sender, subject, content_for_analysis)
                
                # Apply community intelligence
                sender_domain = extract_domain(sender)
                if sender_domain in scam_reports:
                    report_count = scam_reports[sender_domain]
                    risk_analysis['score'] += min(report_count * 10, 30)
                    risk_analysis['flags'].append(f"⚠ {report_count} community reports")
                    
                    if risk_analysis['score'] >= 70:
                        risk_analysis['verdict'] = "● HIGH RISK"
                        risk_analysis['verdict_label'] = "HIGH RISK"
                    elif risk_analysis['score'] >= 40:
                        risk_analysis['verdict'] = "● SUSPICIOUS"
                        risk_analysis['verdict_label'] = "SUSPICIOUS"

                email_list.append({
                    "id": msg['id'],
                    "sender": sender,
                    "subject": subject,
                    "snippet": snippet,
                    "body": content_for_analysis[:500] if content_for_analysis else snippet,
                    "risk": risk_analysis['verdict_label'],
                    "risk_score": risk_analysis['score'],
                    "risk_verdict": risk_analysis['verdict'],
                    "risk_flags": risk_analysis['flags'],
                    "sender_domain": sender_domain,
                    # Additional detection engine fields
                    "email": risk_analysis.get('email', sender),
                    "domain": risk_analysis.get('domain', sender_domain),
                    "claimable_name": risk_analysis.get('claimable_name', 'Unknown'),
                    "is_free_email": risk_analysis.get('is_free_email', False),
                    "email_age": risk_analysis.get('email_age', 'Unknown'),
                    "brand_issues": risk_analysis.get('brand_issues', []),
                    "reputation_score": risk_analysis.get('reputation_score', 50),
                    "issues": risk_analysis.get('issues', []),
                    # ML detection fields
                    "ml_prediction": risk_analysis.get('ml_prediction', 'N/A'),
                    "ml_confidence": risk_analysis.get('ml_confidence', 0.0),
                    "detection_method": risk_analysis.get('detection_method', 'Rule-Based'),
                    "rule_based_score": risk_analysis.get('rule_based_score', 0),
                    "ml_score": risk_analysis.get('ml_score', 0)
                })
            except Exception as e:
                # Skip this email if there's an error
                print(f"Error processing message {msg['id']}: {e}")
                continue

        # Calculate statistics for dashboard
        total_emails = len(email_list)
        safe_count = sum(1 for e in email_list if e['risk'] == 'SAFE')
        phishing_count = sum(1 for e in email_list if e['risk'] == 'HIGH RISK')
        suspicious_count = sum(1 for e in email_list if e['risk'] == 'SUSPICIOUS')
        spam_count = 0  # No spam classification in current system
        
        # Calculate exact percentages for chart
        if total_emails > 0:
            safe_percent = round((safe_count / total_emails) * 100, 1)
            phishing_percent = round((phishing_count / total_emails) * 100, 1)
            suspicious_percent = round((suspicious_count / total_emails) * 100, 1)
            spam_percent = 0
        else:
            safe_percent = phishing_percent = suspicious_percent = spam_percent = 0
        
        # Calculate angles for donut chart (360 degrees total)
        safe_angle = (safe_percent / 100) * 360
        spam_angle = safe_angle + (spam_percent / 100) * 360
        phishing_angle = spam_angle + (phishing_percent / 100) * 360
        suspicious_angle = phishing_angle + (suspicious_percent / 100) * 360
        
        # Determine overall risk level
        if phishing_count > 0:
            overall_risk = "HIGH"
        elif suspicious_count > 0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        stats = {
            "total": total_emails,
            "safe": safe_count,
            "phishing": phishing_count,
            "suspicious": suspicious_count,
            "spam": spam_count,
            "safe_percent": safe_percent,
            "phishing_percent": phishing_percent,
            "suspicious_percent": suspicious_percent,
            "spam_percent": spam_percent,
            "overall_risk": overall_risk,
            # Chart angles
            "safe_angle": safe_angle,
            "spam_angle": spam_angle,
            "phishing_angle": phishing_angle,
            "suspicious_angle": suspicious_angle
        }

        return templates.TemplateResponse("inbox.html", {
            "request": request, 
            "emails": email_list, 
            "stats": stats,
            "user_profile": user_profile
        })
    except Exception as e:
        import traceback
        print(f"❌ Error in inbox: {e}")
        print(f"❌ Traceback: {traceback.format_exc()}")
        return RedirectResponse("/login")

@app.post("/report/{domain}")
def report_scam(domain: str):
    """Handle scam reports from community"""
    scam_reports[domain] += 1
    return {
        "status": "success",
        "domain": domain,
        "total_reports": scam_reports[domain]
    }

@app.get("/inbox/view")
def inbox_view():
    """HTML view of inbox"""
    service = get_gmail_service()
    results = service.users().messages().list(
        userId='me',
        maxResults=20
    ).execute()

    messages = results.get('messages', [])
    analyzed_emails = []

    for msg in messages:
        data = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='metadata'
        ).execute()

        headers = data['payload']['headers']
        sender = subject = ""

        for h in headers:
            if h['name'] == 'From':
                sender = h['value']
            if h['name'] == 'Subject':
                subject = h['value']

        # Get full email body for analysis
        email_body = get_message_body(service, 'me', msg['id'])
        snippet = data.get("snippet", "")
        risk_analysis = calculate_risk(sender, subject, email_body if email_body else snippet)
        
        sender_domain = extract_domain(sender)
        if sender_domain in scam_reports:
            report_count = scam_reports[sender_domain]
            risk_analysis['score'] += min(report_count * 10, 30)
            risk_analysis['flags'].append(f"⚠ {report_count} community reports")
            
            if risk_analysis['score'] >= 70:
                risk_analysis['verdict'] = "● HIGH RISK"
                risk_analysis['verdict_label'] = "HIGH RISK"
            elif risk_analysis['score'] >= 40:
                risk_analysis['verdict'] = "● SUSPICIOUS"
                risk_analysis['verdict_label'] = "SUSPICIOUS"

        analyzed_emails.append({
            'id': msg['id'],
            'sender': sender,
            'sender_domain': sender_domain,
            'subject': subject,
            'snippet': snippet[:100] + '...' if len(snippet) > 100 else snippet,
            'risk_score': risk_analysis['score'],
            'risk_verdict': risk_analysis['verdict'],
            'risk_label': risk_analysis['verdict_label'],
            'risk_flags': risk_analysis['flags']
        })
    
    return HTMLResponse(generate_inbox_html(analyzed_emails))

@app.get("/api/inbox")
def inbox_api():
    """JSON API endpoint for inbox analysis"""
    service = get_gmail_service()
    results = service.users().messages().list(
        userId='me',
        maxResults=20
    ).execute()

    messages = results.get('messages', [])
    analyzed_emails = []
    
    for msg in messages:
        message = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='full'
        ).execute()
        
        headers = message['payload']['headers']
        sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
        snippet = message.get('snippet', '')
        body = get_message_body(message['payload'])
        
        risk_analysis = calculate_risk(sender, subject, f"{snippet} {body}")
        
        analyzed_emails.append({
            'id': msg['id'],
            'sender': sender,
            'subject': subject,
            'date': date,
            'snippet': snippet[:150] + '...' if len(snippet) > 150 else snippet,
            'risk_score': risk_analysis['score'],
            'risk_verdict': risk_analysis['verdict'],
            'risk_label': risk_analysis['verdict_label'],
            'risk_flags': risk_analysis['flags']
        })
    
    return {"emails": analyzed_emails, "total": len(analyzed_emails)}

@app.post("/report/{domain}")
def report_scam(domain: str):
    """Report a sender domain as scam - community intelligence"""
    scam_reports[domain] += 1
    return {
        "success": True,
        "domain": domain,
        "total_reports": scam_reports[domain],
        "message": f"Reported! Total reports for {domain}: {scam_reports[domain]}"
    }

@app.get("/reports")
def get_reports():
    """View all community scam reports"""
    report_rows = ""
    for domain, count in sorted(scam_reports.items(), key=lambda x: x[1], reverse=True):
        report_rows += f"""
        <tr>
            <td style='padding: 15px; border-bottom: 1px solid #eee;'>{domain}</td>
            <td style='padding: 15px; text-align: center; font-weight: bold; color: #f44336; border-bottom: 1px solid #eee;'>{count}</td>
        </tr>
        """
    
    if not report_rows:
        report_rows = "<tr><td colspan='2' style='padding: 30px; text-align: center; color: #999;'>No reports yet. Be the first to report suspicious senders!</td></tr>"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Community Reports - PhishGuard</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #f5f5f5;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 800px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th {{
                background: #667eea;
                color: white;
                padding: 15px;
                text-align: left;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 style='color: #667eea; margin-top: 0;'>🚨 Community Scam Reports</h1>
            <p style='color: #666;'>Crowdsourced intelligence from PhishGuard users</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Sender Domain</th>
                        <th style='text-align: center; width: 150px;'>Reports</th>
                    </tr>
                </thead>
                <tbody>
                    {report_rows}
                </tbody>
            </table>
            
            <div style='text-align: center; margin-top: 30px;'>
                <a href="/inbox" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">← Back to Inbox</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(html)

def extract_domain(email_address):
    """Extract domain from email address"""
    match = re.search(r'@([\w\.-]+)', email_address)
    if match:
        return match.group(1).lower()
    return email_address.lower()

def get_message_body(payload):
    """Extract email body from payload"""
    body = ""
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    import base64
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    break
    elif 'body' in payload and 'data' in payload['body']:
        import base64
        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    
    return body[:500]  # Limit to first 500 chars for analysis

def generate_inbox_html(emails):
    """Generate clean HTML view with big risk labels"""
    
    rows = ""
    for email in emails:
        risk_color = {
            "SAFE": "#4CAF50",
            "SUSPICIOUS": "#FF9800",
            "HIGH RISK": "#F44336"
        }.get(email['risk_label'], "#999")
        
        risk_emoji = {
            "SAFE": "&#x25CF;",
            "SUSPICIOUS": "&#x25CF;",
            "HIGH RISK": "&#x25CF;"
        }.get(email['risk_label'], "&#x25CF;")
        
        # Show only first 2 most important flags
        flags_display = ""
        if email['risk_flags'][:2]:
            for flag in email['risk_flags'][:2]:
                flags_display += f"<div style='color: #666; font-size: 12px; margin-top: 3px;'>• {flag}</div>"
        
        rows += f"""
        <div style='background: white; border-left: 5px solid {risk_color}; margin-bottom: 15px; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; align-items: center; justify-content: space-between;'>
            <div style='flex: 1;'>
                <div style='font-size: 14px; color: #666;'>{email['sender']}</div>
                <div style='font-size: 18px; font-weight: bold; margin: 5px 0;'>{email['subject']}</div>
                <div style='color: #999; font-size: 13px;'>{email['snippet']}</div>
            </div>
            <div style='text-align: center; min-width: 180px; margin: 0 20px;'>
                <div style='font-size: 48px;'>{risk_emoji}</div>
                <div style='font-size: 20px; font-weight: bold; color: {risk_color}; margin: 10px 0;'>{email['risk_label']}</div>
                <div style='color: #666; font-size: 14px;'>Score: {email['risk_score']}</div>
                {flags_display}
            </div>
            <div style='text-align: center;'>
                <button onclick='reportScam(\"{email['sender_domain']}\", this)' style='background: #f44336; color: white; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 14px;'>
                    🚨 Report Scam
                </button>
            </div>
        </div>
        """
    
    safe_count = sum(1 for e in emails if e['risk_label'] == 'SAFE')
    suspicious_count = sum(1 for e in emails if e['risk_label'] == 'SUSPICIOUS')
    high_risk_count = sum(1 for e in emails if e['risk_label'] == 'HIGH RISK')
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishGuard - Inbox</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #f5f5f5;
                margin: 0;
                padding: 20px;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
            }}
            .stats {{
                display: flex;
                gap: 15px;
                margin-bottom: 20px;
                justify-content: center;
            }}
            .stat {{
                background: white;
                padding: 15px 30px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .stat-value {{
                font-size: 32px;
                font-weight: bold;
            }}
        </style>
        <script>
            function reportScam(domain, button) {{
                fetch('/report/' + encodeURIComponent(domain), {{
                    method: 'POST'
                }})
                .then(r => r.json())
                .then(data => {{
                    button.textContent = '✓ Reported (' + data.total_reports + ')';
                    button.style.background = '#666';
                    button.disabled = true;
                    alert('Thanks! This sender has been reported ' + data.total_reports + ' times.');
                    setTimeout(() => location.reload(), 1500);
                }});
            }}
        </script>
    </head>
    <body>
        <div class="header">
            <h1 style='margin: 0; font-size: 36px;'>&#x1F6E1; PhishGuard Inbox</h1>
            <p style='margin: 10px 0 0 0;'>AI-Powered Phishing Detection</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{len(emails)}</div>
                <div>Total</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #4CAF50;">&#x25CF; {safe_count}</div>
                <div>Safe</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #FF9800;">&#x25CF; {suspicious_count}</div>
                <div>Suspicious</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #F44336;">&#x25CF; {high_risk_count}</div>
                <div>High Risk</div>
            </div>
        </div>
        
        <div style='max-width: 1200px; margin: 0 auto;'>
            {rows}
        </div>
        
        <div style='text-align: center; margin-top: 30px; color: #666;'>
            <a href="/" style="color: #667eea; text-decoration: none; font-weight: bold;">← Home</a>
            &nbsp;|&nbsp;
            <a href="/reports" style="color: #667eea; text-decoration: none;">View Community Reports</a>
        </div>
    </body>
    </html>
    """
    
    return html
