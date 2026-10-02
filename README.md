# 🔍 PhishLens — Scan Before You Trust

**TECHFORGE 2026 | Cybersecurity Domain**

**Team Name:** T-48 - Ciphercore

**Project Title:** PhishLens

**Tagline:** Scan before you trust.

---

## 1. Project Overview

PhishLens is a cybersecurity tool designed to help users identify potentially malicious and phishing URLs before interacting with them.

The system analyzes suspicious URLs using URL and domain security indicators and provides a clear risk assessment to help users make safer decisions. PhishLens focuses on the critical few seconds before a user opens an unknown or suspicious link.

---

## 2. Setup & Installation Instructions

### Prerequisites

- Python 3.x
- Git
- Internet connection

### Clone the Repository

```bash
git clone https://github.com/Bhumioza02/T-48-PhishLens.git
````

### Navigate to the Project

```bash
cd T-48-PhishLens
```

### Create a Virtual Environment

```bash
python -m venv venv
```

### Activate the Virtual Environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
streamlit run app.py
```

The application will open in the browser.

---

## 3. Key Features

* 🔗 Suspicious URL scanning
* 🛡️ Phishing URL detection
* 🔍 Domain and URL analysis
* 📊 Risk assessment
* 🤖 AI-assisted explanation of security results
* 🔐 Privacy-focused design
* 🗄️ Database support
* 🧪 Testing support
* ⚡ Fast and user-friendly security analysis
* 🖥️ Simple interface for non-technical users

---

## 4. Technology Stack

### Programming Language

* Python

### Framework

* Streamlit

### Security Analysis

* URL analysis
* Domain analysis
* Phishing detection
* Security indicators
* Risk assessment

### AI

* AI-assisted result explanation

### Database

* Local database support

### Development Tools

* Git
* GitHub
* Python
* Streamlit

---

## 5. Architecture / Workflow

```text
                    USER
                      │
                      ▼
             ┌─────────────────┐
             │   URL INPUT     │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ URL PROCESSING  │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ DOMAIN ANALYSIS │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ PHISHING /      │
             │ THREAT DETECTION│
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ RISK ASSESSMENT │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ AI EXPLANATION  │
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ SECURITY RESULT │
             └─────────────────┘
```

### Workflow

1. User enters a URL.
2. PhishLens processes the submitted URL.
3. URL and domain characteristics are analyzed.
4. Security indicators are evaluated.
5. The detection system identifies suspicious patterns.
6. A risk assessment is generated.
7. The result is displayed to the user.
8. AI-assisted explanation can help the user understand the result.

---

## 6. Dataset / API Information

PhishLens uses URL and domain-related information for security analysis.

The detection system can use URL characteristics and labelled legitimate/phishing URL data to identify suspicious patterns.

If external APIs are configured, they can be used to support additional security and threat analysis.

API keys and sensitive credentials are not included in the repository.

---

## 7. Screenshots / Demo Information

### Local Demo

After installing the dependencies, run:

```bash
streamlit run app.py
```

The application will be available locally at:

```text
http://localhost:8501
```

### Demo Workflow

```text
Enter URL
    ↓
Scan URL
    ↓
Analyze Security Indicators
    ↓
Detect Suspicious Patterns
    ↓
Generate Risk Assessment
    ↓
Display Result
```

### Screenshots

Screenshots of the working PhishLens application can be added to this README to demonstrate:

* PhishLens home screen
  <img width="1895" height="882" alt="image" src="https://github.com/user-attachments/assets/3dd314e3-3d83-4aa5-9b1d-29fac15bb669" />

* URL scanning interface
  <img width="1885" height="915" alt="image" src="https://github.com/user-attachments/assets/ee9b0319-5671-497a-a34b-b072a3eca2c3" />

* Analysis process
* Risk assessment result
  <img width="1502" height="732" alt="image" src="https://github.com/user-attachments/assets/0fbd6ff1-c222-4678-865d-b2fd0d3b5a9e" />

* Security explanation
<img width="1582" height="702" alt="image" src="https://github.com/user-attachments/assets/62f419c8-dc3d-424b-bf77-7e96c8786025" />

---

## 8. Limitations & Future Scope

### Limitations

* No automated phishing detection system can guarantee 100% accuracy.
* Newly created phishing websites may not always be detected.
* Detection depends on available data and security indicators.
* Sophisticated attacks may bypass automated detection.
* External APIs may have availability or rate limitations.
* Results should be treated as security indications rather than absolute guarantees.

### Future Scope

* Real-time threat intelligence integration
* Browser extension
* Mobile application
* Advanced QR-code security analysis
* Domain reputation checking
* Shortened URL and redirect analysis
* Improved machine learning models
* Real-time phishing database integration
* Explainable AI-based security recommendations
* Continuous threat monitoring

---

## 9. Team Members

### T-48 - Ciphercore

* **Bhumi Oza**
* **Payal Ghuge**
* **Kiran Patel**

---
## 🔗 GitHub Repository

[https://github.com/Bhumioza02/T-48-PhishLens](https://github.com/Bhumioza02/T-48-PhishLens)
web link: http://localhost:8502
---

**PHISHLENS — SCAN BEFORE YOU TRUST.**
