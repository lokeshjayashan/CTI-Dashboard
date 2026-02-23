# 🛡️ CTI Dashboard — AI-Based Cyber Threat Intelligence

A real-time AI-powered Cyber Threat Intelligence Dashboard that collects threat data from external APIs, analyzes it using NLP models, stores intelligence in MongoDB, and visualizes findings on a web dashboard.

## Features

- **Threat Analysis** — Analyze IPs, URLs, and free-text threat descriptions
- **AI Classification** — Zero-shot classification using BART-Large-MNLI into categories: malware, phishing, botnet, DDoS, spam, ransomware
- **Topic Detection** — BERTopic-based emerging threat trend detection
- **API Integration** — VirusTotal (URL scanning) and AbuseIPDB (IP reputation)
- **MongoDB Storage** — Persistent storage with API response caching
- **Live Dashboard** — Real-time charts, KPI cards, and threat feed table

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| AI/ML | HuggingFace Transformers (BART), BERTopic, scikit-learn |
| Database | MongoDB |
| Frontend | HTML, CSS, JavaScript, Chart.js |
| APIs | VirusTotal API v3, AbuseIPDB API v2 |

## Setup

### Prerequisites
- Python 3.10+
- MongoDB running locally on `mongodb://localhost:27017`

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/CTI-Dashboard.git
   cd CTI-Dashboard
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set API keys (optional but recommended):
   ```bash
   # Windows PowerShell
   $env:VIRUSTOTAL_API_KEY = "your-key"
   $env:ABUSEIPDB_API_KEY = "your-key"
   ```

4. Start MongoDB:
   ```bash
   mongod
   ```

5. Run the app:
   ```bash
   python app.py
   ```

6. Open http://localhost:5000 in your browser.

## Project Structure

```
CTI DB/
├── app.py                  # Flask app entry point & API routes
├── config.py               # Central configuration
├── requirements.txt        # Python dependencies
├── ingestion/              # External API clients
│   ├── virustotal_client.py
│   └── abuseipdb_client.py
├── processing/             # Text preprocessing
│   └── preprocessor.py
├── intelligence/           # AI/ML models
│   ├── classifier.py       # BART zero-shot classifier
│   └── topic_detector.py   # BERTopic trend detection
├── storage/                # Database layer
│   ├── mongo_client.py
│   └── cache.py
├── templates/
│   └── index.html          # Dashboard HTML
└── static/
    ├── css/style.css        # Dashboard styles
    └── js/dashboard.js      # Frontend logic
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard page |
| `/api/health` | GET | System health check |
| `/api/analyze` | POST | Analyze IP/URL/text |
| `/api/threats` | GET | Recent threat records |
| `/api/stats` | GET | Aggregated statistics |
| `/api/topics` | GET | Emerging threat topics |

## Screenshots

![Dashboard](screenshots/dashboard.png)

## License

MIT
