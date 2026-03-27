# NITDA Phishing Defense System

A Phishing Defense and Detection System designed to protect Nigerian government domains (NITDA, ngCERT, ONSA) against social engineering, domain spoofing attacks, and quishing (QR phishing).

## Project Structure

- `backend/`: FastAPI application and detection engine logic.
- `dashboard/`: Frontend user interface (HTML/TailwindCSS).
- `database/`: SQLite database for logging scans and threats.

## Features

- **Domain Spoof Detection:** Identifies look-alike domains impersonating trusted government entities.
- **AI-Lure Detection:** Scans for high-pressure tactic categories (Urgency, Fear, Authority, Financial).
- **DNS Security Checks:** Validates presence of SPF and DMARC records to catch untrusted sender domains.
- **URL Analysis:** Extracts links from email content and checks for suspicious components (e.g., bit.ly).
- **Quishing Defense:** Allows upload of QR code images to extract and analyze hidden malicious links.
- **Real-time Scoring:** Provides immediate risk assessment and threat levels (Low, Medium, High).
- **Centralized Logging:** Stores scan history in a local SQLite database for threat intelligence analysis.

## Prerequisites

- Python 3.10+
- A modern web browser
- System libraries for zbar (required for QR decoding):
  - Ubuntu/Debian: `sudo apt-get install libzbar0`
  - macOS: `brew install zbar`

## Setup & Startup

### 1. Start the Backend Server

Navigate to the `backend` directory, install dependencies, and start the server using Uvicorn.

```bash
cd backend
# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# .\venv\Scripts\activate   # On Windows

# Install all required dependencies:
pip install fastapi uvicorn pydantic dnspython opencv-python pyzbar numpy python-multipart

# Start the server:
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The backend API will be available at `http://127.0.0.1:8000`.

### 2. Access the Dashboard

Simply open the `dashboard/index.html` file in your web browser.

You can do this by:

- Double-clicking the file in your file explorer.
- Or using a simple local server:
  ```bash
  cd dashboard
  python -m http.server 3000
  ```
  Then visit `http://127.0.0.1:3000` or `http://localhost:3000`.
