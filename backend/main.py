from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import difflib

app = FastAPI()

# Allow Frontend to communicate with Backend
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- DETECTION ENGINE LOGIC ---
TRUSTED_DOMAINS = ["nitda.gov.ng", "ngcert.gov.ng", "onsa.gov.ng"]

def analyze_phishing(email, content):
    """Analyzes text for AI-driven lures and domain spoofing."""
    domain = email.split('@')[-1].lower()
    
    # 1. Domain Spoof Detection (Look-alike domains)
    is_spoof = any(difflib.SequenceMatcher(None, domain, t).ratio() > 0.8 and domain != t for t in TRUSTED_DOMAINS)
    
    # 2. AI-Lure Detection (Keywords common in industrialized social engineering) [cite: 72]
    scam_keywords = ["urgent", "suspend", "verify", "immediately", "action required", "login"]
    score = sum(20 for word in scam_keywords if word in content.lower())
    
    if is_spoof: score += 40 # Heavy penalty for impersonation
    
    # Assign Threat Level [cite: 56]
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return {"score": min(score, 100), "level": level, "is_spoof": is_spoof}

# --- DATABASE INITIALIZATION ---
def init_db():
    conn = sqlite3.connect('../database/security.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY, email TEXT, score INTEGER, level TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.close()

init_db()

# --- API ENDPOINTS ---
class ScanRequest(BaseModel):
    email: str
    content: str

@app.post("/api/scan")
async def scan_email(req: ScanRequest):
    result = analyze_phishing(req.email, req.content)
    # Store result in Database for stats [cite: 18]
    conn = sqlite3.connect('../database/security.db')
    conn.execute('INSERT INTO logs (email, score, level) VALUES (?, ?, ?)', (req.email, result['score'], result['level']))
    conn.commit()
    conn.close()
    return result

@app.get("/api/stats")
async def get_stats():
    conn = sqlite3.connect('../database/security.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE level = 'High'")
    high = cursor.fetchone()[0]
    conn.close()
    return {"total_scans": total, "high_threats": high}