# 🛡️ SentinelNet — AI-Powered Network Intrusion Detection System

<div align="center">

**Production ML system detecting 5 categories of network threats in real-time**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-HuggingFace%20Spaces-blue?style=for-the-badge&logo=huggingface)](https://huggingface.co/spaces/Hitan2004/sentinelnet)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github)](https://github.com/Hitan547/sentinelnet)
[![Python](https://img.shields.io/badge/Python-3.10-blue?style=for-the-badge&logo=python)](#tech-stack)
[![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?style=for-the-badge)](#tech-stack)

*A full-stack real-time intrusion detection dashboard with hybrid frontend, REST API, and automated CI/CD deployment.*

</div>

---

## 🎯 Overview

SentinelNet is a production-grade network intrusion detection system that analyzes live traffic and batch CSV datasets to classify connections into 5 threat categories. Built with a Random Forest classifier trained on the NSL-KDD dataset, it combines real-time inference with a sophisticated web dashboard and self-correcting batch processing.

### ⚡ Key Capabilities

| Feature | Capability |
|---------|-----------|
| **Real-Time Detection** | 1000s of live packets/sec through trained ML model |
| **Threat Classification** | 5-class detection: normal, DoS, Probe, R2L, U2R |
| **Batch Analysis** | Process CSVs with live progress, streaming predictions, auto-generated threat reports |
| **Visual Intelligence** | Live timeline, activity heatmaps, confidence distributions, attack patterns |
| **Export Formats** | CSV, PDF reports, JSON for integration |
| **Deployment** | Docker containerized, live on HuggingFace Spaces |

---

## 🏗️ Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   SentinelNet System                     │
└─────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │   Flask Backend  │
                    │   (app.py)       │
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐       ┌─────▼──────┐
    │ /health  │         │/predict │       │ /static    │
    │ Endpoint │         │ Batch   │       │ Frontend   │
    └──────────┘         │ Inference│      └────────────┘
                         └────┬────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
         ┌────▼──────┐   ┌────▼─────┐   ┌───▼──────────┐
         │ML Pipeline│   │One-Hot    │   │Label         │
         │Processing │   │Encoder    │   │Encoder       │
         └───────────┘   └───────────┘   └──────────────┘
              │
         ┌────▼──────────────────────┐
         │ Random Forest Classifier  │
         │ (sentinel_brain.joblib)   │
         │ 41 NSL-KDD Features       │
         └───────────────────────────┘
```

### Data Flow

```
User Input (Live or CSV)
    ↓
Feature Extraction & Validation
    ↓
One-Hot Encoding (protocol_type, flag)
    ↓
Frequency Encoding (service)
    ↓
Log Transforms (src_bytes, dst_bytes, duration)
    ↓
Feature Engineering (total_bytes, ratios, error flags)
    ↓
Standard Scaling (all features)
    ↓
Random Forest Inference
    ↓
Prediction + Confidence Score
    ↓
Severity Mapping
    ↓
JSON Response / Dashboard Update
```

---

## 📊 Model Performance

### Training Details

- **Algorithm**: Random Forest Classifier (100 trees)
- **Dataset**: NSL-KDD (improved KDD Cup 1999)
- **Features**: 41 network connection attributes
- **Classes**: 5 (normal, DoS, Probe, R2L, U2R)
- **Preprocessing**: OHE, frequency encoding, log transforms, standard scaling

### Threat Categories

| Class | Type | Severity | Examples |
|-------|------|----------|----------|
| `normal` | Clean traffic | ✅ None | HTTP requests, DNS queries |
| `DoS` | Denial of Service | 🔴 **Critical** | SYN floods, UDP storms |
| `Probe` | Reconnaissance | 🟠 Medium | Port scanning, OS fingerprinting |
| `R2L` | Remote to Local | 🔴 High | SSH brute force, FTP attacks |
| `U2R` | User to Root | 🔴 **Critical** | Buffer overflow, privilege escalation |

---

## ✨ Features

### 📡 Live Monitor Tab
Real-time threat detection with auto-generated NSL-KDD formatted packets

- **Auto-Generation**: Simulates realistic network traffic packets
- **Real-Time Inference**: Each packet sent to trained model instantly
- **Live Detection Feed**: Class, confidence, severity per packet
- **Attack Distribution Chart**: Bar chart updating in real-time
- **Threat Timeline**: Last 60 seconds of activity
- **Activity Heatmap**: 60×8 grid of recent packets
- **Confidence Distribution**: Histogram of model certainty
- **System Log**: Terminal-style event log
- **Session Summary**: Total packets, attacks detected, accuracy metrics

### 📂 CSV Analysis Tab
Upload and analyze NSL-KDD formatted datasets with streaming predictions

- **Smart Header Detection**: Auto-detects with or without column names
- **Batch Processing**: Optimized row-by-row inference through model
- **Live Progress**: Real-time bar with ETA and processing speed (rows/sec)
- **Streaming Results**: Predictions appear as they're computed
- **Threat Report Generation** (on completion):
  - Risk score gauge (0–100)
  - Class distribution bar chart
  - Confidence waveform over entire dataset
  - Threat intensity rolling average
  - Protocol breakdown pie chart
  - Top targeted services
  - Attack pattern clustering visualization
  - Paginated full results table with sorting/filtering
- **Multi-Format Export**: CSV, PDF report, JSON

---

## 🧠 ML Pipeline Deep Dive

### Feature Engineering

```python
# Input: 41 raw NSL-KDD features
features_raw = {
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate'
}

# Preprocessing Pipeline
1. One-hot encoding: protocol_type (3 categories) → 3 columns
2. One-hot encoding: flag (11 categories) → 11 columns
3. Frequency encoding: service → maps to frequency rank
4. Log transforms: log(1 + src_bytes), log(1 + dst_bytes), log(1 + duration)
5. Feature engineering:
   - total_bytes = src_bytes + dst_bytes
   - src_bytes_ratio = src_bytes / (total_bytes + 1)
   - is_error_flag = 1 if error flag present
6. Standard scaling: (x - mean) / std for all numeric features

# Output: 41 standardized features → Random Forest inference
```

### Serialization

All pipeline artifacts are serialized with `joblib` for production reliability:

```
models/
├── sentinel_brain.joblib       # Trained Random Forest (100 trees)
├── label_encoder.joblib        # Encodes target class labels
├── ohe_encoder.joblib          # One-hot encoder for protocol/flag
├── freq_map.joblib             # Service frequency mapping dictionary
├── scaler.joblib               # StandardScaler fitted on training data
└── selected_features.joblib    # List of 41 selected features in order
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip or conda
- 500MB disk space for models

### Local Setup (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/Hitan547/sentinelnet.git
cd sentinelnet

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run Flask server
python app.py

# 5. Open browser
# → http://localhost:7860
```

### Docker Setup (for Spaces or cloud deployment)

```bash
# Build image
docker build -t sentinelnet:latest .

# Run container
docker run -p 7860:7860 sentinelnet:latest

# Access at http://localhost:7860
```

### Deployment on HuggingFace Spaces

1. Create new Space on HuggingFace
2. Select "Docker" runtime
3. Clone this repo
4. Push to Space repo
5. Auto-deploys and serves live

---

## 🔌 REST API Reference

### POST `/predict`
Batch inference endpoint for NSL-KDD formatted network packets

**Request:**
```json
{
  "rows": [
    {
      "duration": 0,
      "protocol_type": "tcp",
      "service": "http",
      "flag": "SF",
      "src_bytes": 181,
      "dst_bytes": 5450,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 0,
      "num_failed_logins": 0,
      "logged_in": 1,
      "num_compromised": 0,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 0,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 1,
      "srv_count": 1,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 1,
      "dst_host_srv_count": 1,
      "dst_host_same_srv_rate": 1.0,
      "dst_host_diff_srv_rate": 0.0,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0
    }
  ]
}
```

**Response:**
```json
{
  "status": "ok",
  "results": [
    {
      "predicted_class": "normal",
      "severity": "None",
      "confidence": 0.9821,
      "is_intrusion": false
    }
  ]
}
```

### GET `/health`
System health check

**Response:**
```json
{
  "status": "online",
  "model": "sentinel_brain",
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

---

## 📁 Project Structure

```
sentinelnet/
├── frontend/
│   ├── index.html          # Main HTML with tabs, charts, tables
│   ├── style.css           # CSS variables, grid layout, animations
│   └── app.js              # Canvas charts, API calls, event handlers
├── models/
│   ├── sentinel_brain.joblib          # Random Forest classifier
│   ├── label_encoder.joblib           # Target label encoding
│   ├── ohe_encoder.joblib             # Protocol/flag one-hot encoder
│   ├── freq_map.joblib                # Service frequency dictionary
│   ├── scaler.joblib                  # Standard scaler
│   └── selected_features.joblib       # 41 feature names + order
├── app.py                 # Flask server + /predict + /health endpoints
├── requirements.txt       # Python dependencies (Flask, scikit-learn, etc.)
├── Dockerfile            # Multi-stage build for HuggingFace Spaces
├── .dockerignore         # Excludes unnecessary files from build
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions CI pipeline
└── README.md             # This file
```

---

## 🔄 CI/CD Pipeline

### Continuous Integration (GitHub Actions)

```yaml
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Syntax check
        run: python -m py_compile app.py
      - name: Health check (skip models)
        env:
          SKIP_MODEL: true
        run: python app.py &
             sleep 2
             curl http://localhost:7860/health
      - name: Docker build test
        run: docker build -t sentinelnet:test .
```

**CI Features:**
- ✅ Python 3.10 environment setup
- ✅ Dependency installation verification
- ✅ Code syntax validation
- ✅ Flask app health check (with `SKIP_MODEL=true` to avoid model loading timeout)
- ✅ Docker image build validation

### Continuous Deployment (HuggingFace Spaces)

- **Trigger**: Push to `main` branch
- **Action**: Auto-deploys Docker container to HuggingFace Spaces
- **Endpoint**: https://huggingface.co/spaces/Hitan2004/sentinelnet
- **Uptime**: Always available (free tier with occasional cold starts)

---

## 🎓 What I Learned

✅ **Production ML Systems**
- Training and deploying multi-class classification models end-to-end
- Feature engineering and preprocessing pipeline serialization
- Model serving via REST API with batch inference

✅ **Real-Time Dashboards**
- Building interactive dashboards with vanilla JavaScript
- Canvas API for high-performance charting (thousands of data points)
- Responsive design for desktop and tablet

✅ **Backend Engineering**
- Flask REST API design and CORS handling
- Batch processing with streaming progress feedback
- Error handling and validation

✅ **DevOps & Deployment**
- Docker containerization for reproducible environments
- HuggingFace Spaces deployment workflow
- GitHub Actions CI/CD pipeline with smart skipping

✅ **Advanced Concepts**
- NSL-KDD dataset characteristics and threat modeling
- One-hot vs. frequency encoding trade-offs
- Log transforms for skewed feature distributions
- Cross-entropy loss and feature importance in Random Forest

---

## 📊 Dataset Reference

**NSL-KDD Dataset**
- Improved version of KDD Cup 1999
- **Size**: 125,973 training records, 22,544 test records
- **Features**: 41 network connection attributes
- **Classes**: 5 (normal, DoS, Probe, R2L, U2R)
- **Advantages**: Removes duplicate records, more balanced class distribution
- **Standard**: Widely used benchmark for IDS research

**Attribute Categories:**
- Basic features (10): duration, protocol, service, flag, bytes
- Content features (13): hot, num_failed_logins, logged_in, compromised, etc.
- Time-based traffic features (9): count, srv_count, serror_rate, etc.
- Host-based traffic features (9): dst_host_count, dst_host_srv_count, etc.

---

## 🤝 Contributing

This is a portfolio project, but you're welcome to fork and extend!

**Ideas for enhancement:**
- [ ] Add LSTM-based temporal anomaly detection
- [ ] Implement feature importance visualization
- [ ] Add real PCAP file ingestion
- [ ] Multi-model ensemble (XGBoost + Neural Network)
- [ ] Real-time alerting webhook integration

---

## 📜 License

MIT License — Use freely for learning, portfolio, or production purposes.

---

## 📞 Contact

**Hitan K** — AI Systems Engineer

- 🔗 [LinkedIn](https://linkedin.com/in/hitan-k)
- 🐙 [GitHub](https://github.com/Hitan547)
- 🤗 [HuggingFace](https://huggingface.co/Hitan2004)
- 📧 [Email](mailto:hitan.k@outlook.com)

---

<div align="center">

**⭐ If this helped you, please star the repo! ⭐**

*Built with ❤️ for production and learning.*

</div>
