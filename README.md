# 🛡️ PHISHLENS
> *"Scan before you trust."*

PhishLens is a rapid 3-second cybersecurity intelligence dashboard built for hackathons to protect everyday users from malicious links, lookalike phishing domains, and rogue UPI payment QR codes.

---

## ⚡ Problem Statement

A user scans a QR at a shop or taps a “KYC update” link on WhatsApp and has about **3 seconds** to decide. PhishLens provides instant, deterministic threat analysis:

- **Lookalike & Homoglyph Detection**: Catches spoofed bank, wallet, and government domains (e.g., unicode tricks, typosquatting).
- **UPI QR Deep Analysis**: Decodes VPAs, payee names, and identifies fraudulent payment-request scenarios.
- **SSRF-Safe Redirect Expansion**: Safely unshortens redirect chains with loopback and private IP blocking.
- **Zero-Leak Privacy**: Raw query parameter values are hashed before storage; plain secrets are never logged.
- **Transparent Scoring**: Deterministic rules produce **SAFE**, **CAUTION**, or **DANGER** with a 1-sentence plain-English summary.

---

## 📁 Project Architecture

```text
PhishLens/
│
├── app.py                  # Streamlit dashboard with modern cyber SaaS UI
├── config.py               # Constants, risk thresholds, and branding
├── detector.py             # Security orchestrator combining all analyzers
├── url_analyzer.py         # URL structural and pattern analysis
├── domain_analyzer.py      # Unicode homoglyph and brand lookalike detection
├── redirect_analyzer.py    # Safe redirect unshortening & SSRF protection
├── qr_scanner.py           # QR image payload extraction
├── upi_analyzer.py         # UPI payment safety verification
├── risk_engine.py          # Deterministic risk scoring (SAFE/CAUTION/DANGER)
├── ai_explainer.py         # Plain-English one-sentence threat summarizer
├── database.py             # SQLite scan history logging
├── privacy.py              # SHA-256 query parameter hashing
├── requirements.txt        # Dependencies manifest
├── README.md               # Project documentation
│
├── data/
│   └── trusted_brands.json # Legitimate banks, wallets, & government portals
│
└── tests/
    └── test_basic.py       # Basic test suite
```

---

## 🚀 Getting Started (Step 1)

### 1. Requirements
- Python 3.10+ (Tested on Python 3.14)

### 2. Install Dependencies
Open your PowerShell or Terminal inside the `PhishLens` directory and run:
```powershell
python -m pip install -r requirements.txt
```

### 3. Launch the Application
```powershell
python -m streamlit run app.py
```

### 4. View in Browser
Open: [http://localhost:8501](http://localhost:8501)
