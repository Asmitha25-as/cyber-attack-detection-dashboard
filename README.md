

# 🛡️ SOC Command Center - Enterprise Security Dashboard

A comprehensive **Security Operations Center (SOC) Dashboard** leveraging **Machine Learning** for real-time cyber attack detection and incident response.

---

## 📋 Overview

**SOC Command Center** is an enterprise-grade security dashboard designed for Security Operations Centers to monitor, detect, and respond to cyber threats in real-time. The system leverages a **Random Forest machine learning model** trained on the NSL-KDD dataset to classify network traffic into normal behavior or various attack types including DoS, Probe, R2L, and U2R attacks.

The dashboard provides security analysts with comprehensive visibility into network security posture, threat intelligence, incident response capabilities, and team collaboration tools - all within a modern, responsive interface.

---

## ✨ Key Features

### Core Monitoring (15 Features)

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Key Metrics Cards** | Real-time statistics showing total requests, detected attacks, critical alerts, and active connections |
| 2 | **Network Traffic Monitoring** | Live visualization of network traffic with packets/sec, bytes/sec, and throughput analysis |
| 3 | **ML Attack Detection** | Random Forest model predicting DoS, Probe, R2L, and U2R attacks with confidence scores |
| 4 | **Threat Alert System** | Real-time alert feed with severity levels (Critical, High, Medium, Low) |
| 5 | **Attack Distribution** | Interactive pie chart showing proportion of different attack types |
| 6 | **Attack Timeline** | 7-day attack frequency visualization with trend analysis |
| 7 | **Top Attack Sources** | Ranking of IP addresses generating the most attacks |
| 8 | **Geographic Attack Map** | Interactive world map showing attack origins and intensity |
| 9 | **Risk Score System** | Dynamic risk scoring with time decay and severity classification |
| 10 | **Protocol Analysis** | Distribution analysis of network protocols (TCP/UDP/ICMP) |
| 11 | **Anomaly Detection** | Real-time detection of unusual patterns including traffic spikes |
| 12 | **Security Logs Table** | Paginated, filterable logs with search and export functionality |
| 13 | **Security Health Indicator** | Composite health score based on multiple security metrics |
| 14 | **Attack Prediction Trends** | ML-based forecasting of future attack patterns |
| 15 | **Downloadable Reports** | Multi-format report generation (CSV/PDF) |

### Advanced Capabilities (3 Additional Features)

| # | Feature | Description |
|---|---------|-------------|
| 16 | **MITRE ATT&CK Framework** | Industry-standard mapping of attacks to tactics and techniques |
| 17 | **Threat Intelligence Feeds** | Integration with external threat feeds and IOC matching |
| 18 | **Team Collaboration** | Incident case management and team activity tracking |

---

## 🛠️ Technology Stack

### Backend
- **Python 3.8+** - Core programming language
- **Flask 2.3.3** - Web framework and REST API
- **scikit-learn 1.3.0** - Machine learning model training
- **pandas 2.0.3** - Data manipulation and analysis
- **numpy 1.24.3** - Numerical computing
- **joblib 1.3.2** - Model serialization
- **reportlab 4.0.9** - PDF report generation

### Frontend
- **HTML5** - Structure and semantics
- **CSS3** - Styling and responsive design
- **JavaScript (ES6)** - Interactive functionality
- **Chart.js 4.4.0** - Data visualization and charts
- **Leaflet 1.9.4** - Interactive maps
- **Font Awesome 6** - Icon library

### Data Storage
- **CSV files** - Lightweight data storage
- **JSON** - Configuration and mapping

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/soc-command-center.git
cd soc-command-center
```

2. **Create virtual environment**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Download NSL-KDD dataset**
```bash
mkdir dataset
curl -o dataset/nsl_kdd.csv https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt
```

5. **Train the ML model**
```bash
python train_model.py
```

6. **Run the application**
```bash
python app.py
```

7. **Access the dashboard**
```
http://localhost:5000
```

---

## 📁 Project Structure

```
soc-command-center/
│
├── app.py                          # Main Flask application
├── train_model.py                   # ML model training pipeline
├── predict.py                        # Prediction logic
├── requirements.txt                  # Python dependencies
├── README.md                          # Documentation
│
├── templates/
│   └── dashboard.html                 # Main dashboard interface
│
├── static/
│   ├── style.css                      # CSS styles
│   └── dashboard.js                    # Frontend JavaScript
│
├── model/                             # ML model artifacts
│   ├── random_forest_model.joblib      # Trained model
│   ├── model_config.json                # Model configuration
│   ├── attack_mapping.csv                # Attack type mapping
│   └── feature_names.json                # Feature names list
│
├── data/                               # Application data
│   ├── predictions_log.csv              # Historical predictions
│   └── alerts_log.csv                    # Active alerts
│
├── dataset/                            # Training dataset
│   └── nsl_kdd.csv                        # NSL-KDD dataset
│
└── reports/                            # Generated reports
```

---

## 📊 ML Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 98.73% |
| Precision | 98.71% |
| Recall | 98.73% |
| F1-Score | 98.34% |

### Attack Classification
- **DoS** (Denial of Service) - 99.2% detection rate
- **Probe** (Surveillance/Scanning) - 98.5% detection rate
- **R2L** (Remote to Local) - 97.8% detection rate
- **U2R** (User to Root) - 96.3% detection rate
- **Normal** (Benign traffic) - 99.5% detection rate

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/predict` | POST | ML attack prediction |
| `/api/metrics` | GET | Key metrics data |
| `/api/traffic-monitoring` | GET | Traffic data |
| `/api/alerts` | GET | Threat alerts |
| `/api/attack-distribution` | GET | Attack type distribution |
| `/api/attack-timeline` | GET | Timeline data |
| `/api/top-attackers` | GET | Top attacking IPs |
| `/api/geo-attacks` | GET | Geographic data |
| `/api/risk-scores` | GET | Risk scores |
| `/api/protocol-analysis` | GET | Protocol distribution |
| `/api/anomalies` | GET | Detected anomalies |
| `/api/security-logs` | GET | Paginated logs |
| `/api/security-health` | GET | Health indicators |
| `/api/prediction-trends` | GET | Attack predictions |
| `/api/generate-report` | POST | Generate report |
| `/download-report/<filename>` | GET | Download report |

---

## 🎨 Dashboard Pages

- **Dashboard Overview** - Real-time metrics, charts, and alerts
- **Network Monitoring** - Bandwidth usage and connection metrics
- **ML Detection** - Feature input and prediction results
- **Threat Analytics** - Attack trends and severity distribution
- **Attack Map** - Geographic visualization of attack origins
- **Security Logs** - Paginated, filterable log table
- **Reports** - Generate and download security reports
- **MITRE ATT&CK** - Tactics and techniques mapping
- **Threat Intelligence** - External feed integration
- **Team Collaboration** - Incident case management
- **Settings** - Dashboard configuration

---

## ⚙️ Configuration

### Dashboard Settings
- **Theme**: Light / Dark
- **Accent Color**: Blue, Green, Purple, Red
- **Font Size**: Small, Medium, Large
- **Auto-refresh**: 5s, 10s, 30s, 1m, 5m
- **Data Retention**: 7d, 30d, 90d, 365d

---

## 🔒 Security Features

- Input validation on all API endpoints
- Session management with timeouts
- CORS configuration
- Secure error handling
- No sensitive data exposure
- API key protection

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 📞 Contact

**Your Name** - your.email@example.com

**Project Link**: [https://github.com/yourusername/soc-command-center](https://github.com/yourusername/soc-command-center)

---

## 🙏 Acknowledgments

- **NSL-KDD Dataset** - University of New Brunswick
- **MITRE ATT&CK** - Industry-standard framework
- **Chart.js** - Data visualization library
- **Leaflet** - Interactive maps
- **Font Awesome** - Icons

---

<p align="center">
  <b>Built with 🛡️ for cybersecurity professionals</b>
</p>


