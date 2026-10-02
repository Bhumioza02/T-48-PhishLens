# 🔍 PhishLens — Scan Before You Trust

## TECHFORGE 2026 | Cybersecurity Domain

**Team Name:** T-48 - Ciphercore

**Project Title:** PhishLens

**Tagline:** Scan before you trust.

---

## 🚨 Project Overview

PhishLens is a cybersecurity tool designed to help users identify potentially malicious and phishing URLs before interacting with them.

The system analyzes suspicious URLs and provides a clear risk assessment to help users make safer decisions. PhishLens is designed around the critical 3-second decision a user makes before opening an unknown link or scanning a QR code.

---

## 🎯 Problem Statement

A user scans a QR at a shop or taps a “KYC update” link on WhatsApp and has about 3 seconds to decide. Build PhishLens, a scanning tool that decodes the QR or URL, expands shorteners and redirect chains, and scores the final destination. It must detect lookalike and homoglyph domains imitating banks, wallets and government sites; newly registered domains; suspicious URL structure; and, for UPI QR codes, a payee name that does not match the shop or a “collect” trick telling the user they will receive money. The verdict (Safe / Caution / Danger) comes with one sentence a non-technical person understands, and logs store only hashed query parameters. 

---

## 💡 Our Solution

PhishLens allows users to submit a suspicious URL for analysis and receive an understandable security assessment.

The system examines security-related characteristics of the URL and identifies potentially suspicious patterns.

The goal is simple:

> **Scan first. Understand the risk. Then decide.**

---

## ✨ Key Features

- 🔗 URL scanning and analysis
- 📷 QR code URL detection and analysis
- 🛡️ Phishing and suspicious URL detection
- ⚡ Fast security assessment
- 📊 Security indicator analysis
- 🚨 Clear risk classification
- 🖥️ Simple and user-friendly interface
- 🔍 Helps users identify suspicious links before opening them

---

## 🔄 Architecture / Workflow

```text
                    USER
                      │
                      ▼
             ┌─────────────────┐
             │ URL / QR INPUT  │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ URL EXTRACTION  │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ FEATURE         │
             │ ANALYSIS        │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ PHISHING / RISK │
             │ DETECTION       │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ RISK ASSESSMENT │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ SECURITY RESULT │
             └─────────────────┘

🛠️ Technology Stack
Programming Language
Python
Interface
Streamlit
Cybersecurity / Analysis
URL parsing
URL feature extraction
Phishing detection
QR code processing
Development Tools
Git
GitHub
Python
⚙️ Setup & Installation
1. Clone the repository
git clone https://github.com/YOUR-GITHUB-USERNAME/T-48-PhishLens.git
2. Open the project folder
cd T-48-PhishLens
3. Create a virtual environment
python -m venv venv
4. Activate the virtual environment
Windows
venv\Scripts\activate
Linux / macOS
source venv/bin/activate
5. Install dependencies
pip install -r requirements.txt
6. Run the application
streamlit run app.py

The application will open in the browser.

📂 Project Structure
T-48-PhishLens/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── models/
├── utils/
└── screenshots/
📊 Dataset / API Information

PhishLens uses URL-related security indicators to identify potentially suspicious URLs.

The detection system can use labelled URL data containing legitimate and phishing examples for analysis and model development.

Any external dataset or API used by the implementation is used only for cybersecurity analysis and threat detection.

🖥️ Demo

The PhishLens prototype demonstrates the following workflow:

Enter / Scan URL
       ↓
Analyze URL
       ↓
Extract Security Indicators
       ↓
Detect Suspicious Patterns
       ↓
Generate Risk Assessment
       ↓
Display Result

Screenshots and demonstration material are included in the repository.

🔐 Security Considerations

PhishLens is designed as an additional security layer to help users identify potentially dangerous links before interacting with them.

Users should still follow standard cybersecurity practices:

Do not open unknown links.
Verify website domains carefully.
Never share passwords or OTPs with unknown websites.
Use multi-factor authentication.
Keep operating systems and applications updated.
Avoid downloading files from untrusted sources.
⚠️ Limitations
No phishing detection system can guarantee 100% accuracy.
Newly created phishing websites may not always be detected.
Detection depends on the available security indicators and data.
External APIs may have availability or rate limitations.
Sophisticated attacks may bypass automated detection systems.
🚀 Future Scope

Future improvements for PhishLens include:

Real-time threat intelligence integration
Browser extension
Mobile application
Advanced QR code security analysis
Domain reputation checking
Shortened URL and redirect analysis
Improved machine learning models
Real-time phishing database integration
Explainable AI-based security recommendations
Continuous threat monitoring
🎯 Impact

PhishLens aims to make phishing detection faster and easier for everyday users.

Instead of blindly opening a suspicious link, users can check it first and understand the potential risk.

Scan → Analyze → Understand → Decide
👥 Team
T-48 - Ciphercore

Team Members:
Payal Ghuge
Bhumi Oza
Kiran Patel
🏆 Hackathon

TECHFORGE 2026

Domain: Cybersecurity

Project: PhishLens

Team: T-48 - Ciphercore

Tagline: Scan before you trust.

📜 Disclaimer

PhishLens is developed as a cybersecurity hackathon project for educational and demonstration purposes.

The results provided by the system should be treated as a security indication and not as an absolute guarantee that a URL is safe or malicious.

⭐ Project Goal

PHISHLENS — SCAN BEFORE YOU TRUST.

**Before submitting:** replace only `Team Member 2` and `YOUR-GITHUB-USERNAME`. Also, if your actual main Python file is **not `app.py`**, tell me the filename or send your GitHub repository screenshot—I’ll correct those commands so the README matches your actual working project.
