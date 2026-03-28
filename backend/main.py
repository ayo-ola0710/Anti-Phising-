import os
import re
import sqlite3
import difflib
import dns.resolver
import numpy as np
import cv2
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# --- CONFIGURATION ---
DB_PATH = os.path.join(os.path.dirname(__file__), "../database/security.db")
TRUSTED_DOMAINS = ["nitda.gov.ng", "ngcert.gov.ng", "onsa.gov.ng"]

# Allow Frontend to communicate with Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- DATABASE INITIALIZATION ---
def init_db():
    try:
        # Create database directory if it doesn't exist to prevent errors
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''CREATE TABLE IF NOT EXISTS logs 
                    (id INTEGER PRIMARY KEY, email TEXT, score INTEGER, level TEXT, is_spoof BOOLEAN, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.close()
    except Exception as e:
        print(f"Error initializing database: {e}")

init_db()

# --- DETECTION ENGINE LOGIC ---
def check_dns_security(domain):
    """Checks for SPF and DMARC records for a domain."""
    results = {"spf": False, "dmarc": False}
    try:
        # Check SPF (TXT record on root domain)
        answers = dns.resolver.resolve(domain, 'TXT')
        results["spf"] = any("v=spf1" in str(r).lower() for r in answers)
    except Exception:
        pass

    try:
        # Check DMARC (TXT record on _dmarc sub-domain)
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        results["dmarc"] = any("v=dmarc1" in str(r).lower() for r in dmarc_answers)
    except Exception:
        pass
    
    return results

def analyze_phishing(email, content):
    """Analyzes text for AI-driven lures, domain spoofing, malicious URLs, and DNS security."""
    domain = email.split('@')[-1].lower()
    
    # 1. Domain Spoof Detection (Look-alike domains)
    is_spoof = any(difflib.SequenceMatcher(None, domain, t).ratio() > 0.8 and domain != t for t in TRUSTED_DOMAINS)
    
    # 2. URL Analysis
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, content)
    suspicious_urls = [url for url in urls if any(keyword in url for keyword in ["bit.ly", "tinyurl", "login", "verify", "secure"])]
    
    # 3. DNS Security (SPF/DMARC)
    dns_check = check_dns_security(domain)
    
    # 4. Social Engineering Tactic Detection (Heuristic AI-Lure Simulation) [cite: 72]
    tactics = {
        "urgency": ["urgent", "immediately", "as soon as possible", "final notice", "within 24 hours"],
        "fear/threat": ["suspend", "block", "deactivate", "legal action", "compromised", "unauthorized"],
        "authority/trust": ["official", "security department", "administrator", "nitda support", "verification required"],
        "financial": ["refund", "invoice", "payment", "bank", "claim", "prize"]
    }
    
    tactical_score = 0
    detected_tactics = []
    
    content_lower = content.lower()
    for tactic, keywords in tactics.items():
        if any(word in content_lower for word in keywords):
            tactical_score += 20
            detected_tactics.append(tactic)
    
    score = tactical_score
    
    if is_spoof: score += 40 # Heavy penalty for impersonation
    if suspicious_urls: score += 30 # Penalty for suspicious links
    if not dns_check["spf"]: score += 15 # Missing SPF
    if not dns_check["dmarc"]: score += 10 # Missing DMARC
    
    # Assign Threat Level
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return {
        "score": min(score, 100), 
        "level": level, 
        "is_spoof": is_spoof, 
        "url_count": len(urls),
        "dns_security": dns_check,
        "tactics_detected": detected_tactics
    }

# --- QUISHING DETECTION (QR CODE) ---
def decode_qr(image_bytes):
    """Decodes QR code from image bytes using pyzbar/opencv."""
    try:
        from pyzbar.pyzbar import decode
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        decoded_objects = decode(img)
        for obj in decoded_objects:
            return obj.data.decode("utf-8")
    except ImportError:
        return "ERROR: pyzbar or zbar library missing"
    except Exception as e:
        return f"ERROR: {str(e)}"
    return None

# --- FRONTEND ROUTE ---
FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "../dashboard/index.html")

@app.get("/")
async def frontend():
    return FileResponse(FRONTEND_PATH)

# --- API ENDPOINTS ---
class ScanRequest(BaseModel):
    email: str
    content: str

@app.post("/api/scan")
async def scan_email(req: ScanRequest):
    result = analyze_phishing(req.email, req.content)
    # Store result in Database for stats
    conn = sqlite3.connect(DB_PATH)
    conn.execute('INSERT INTO logs (email, score, level, is_spoof) VALUES (?, ?, ?, ?)', 
                 (req.email, result['score'], result['level'], result['is_spoof']))
    conn.commit()
    conn.close()
    return result

@app.post("/api/quish")
async def scan_qr(file: UploadFile = File(...)):
    """Extracts URL from QR code and analyzes it."""
    contents = await file.read()
    extracted_url = decode_qr(contents)
    
    if not extracted_url:
        return {"error": "No QR code found in image"}
    if extracted_url.startswith("ERROR"):
        return {"error": extracted_url}
    
    # Analyze the extracted URL using the phishing engine
    # We'll treat the URL as the "content" and use a dummy sender
    result = analyze_phishing("scanner@quish.local", extracted_url)
    result["extracted_url"] = extracted_url
    return result

@app.get("/api/stats")
async def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE level = 'High'")
    high = cursor.fetchone()[0]
    conn.close()
    return {"total_scans": total, "high_threats": high}