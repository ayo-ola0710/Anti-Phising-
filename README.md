# NITDA Phishing Defense System

A Phishing Defense and Detection System designed to protect Nigerian government domains (NITDA, ngCERT, ONSA) against social engineering and domain spoofing attacks.

## Project Structure

- `backend/`: FastAPI application and detection engine logic.
- `dashboard/`: Frontend user interface (HTML/TailwindCSS).
- `database/`: SQLite database for logging scans and threats.

## Prerequisites

- Python 3.10+
- A modern web browser

## Setup & Startup

### 1. Start the Backend Server

Navigate to the `backend` directory and start the server using Uvicorn.

```bash
cd backend
# If you haven't created a venv:
# python -m venv venv
# source venv/bin/activate  # On Linux/macOS
# .\venv\Scripts\activate   # On Windows
# pip install fastapi uvicorn pydantic

# Start the server:
./venv/bin/uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The backend will be available at `http://127.0.0.1:8000`.

### 2. Access the Dashboard

Simply open the `dashboard/index.html` file in your web browser. 

You can do this by:
- Double-clicking the file in your file explorer.
- Or using a simple local server:
  ```bash
  cd dashboard
  python -m http.server 3000
  ```
  Then visit `http://127.0.0.1:3000`.

## Features

- **Domain Spoof Detection:** Identifies look-alike domains impersonating trusted government entities.
- **AI-Lure Detection:** Scans for high-pressure keywords common in industrialized social engineering.
- **Real-time Scoring:** Provides immediate risk assessment and threat levels.
- **Centralized Logging:** Stores scan history for threat intelligence analysis.
