
# 🛡️ SOC Command Center - Cyber Attack Detection Dashboard

**AI-Powered Security Operations Center with Machine Learning for Real-Time Threat Detection**

---

## 🎯 Overview

**SOC Command Center** is an enterprise-grade security dashboard designed for Security Operations Centers to monitor, detect, and respond to cyber threats in real-time. The system leverages a **Random Forest machine learning model** trained on the NSL-KDD dataset to classify network traffic into normal behavior or various attack types including DoS, Probe, R2L, and U2R attacks.

The dashboard provides security analysts with comprehensive visibility into network security posture, threat intelligence, incident response capabilities, and team collaboration tools - all within a modern, responsive interface.

---

## 🌟 Key Highlights

- 🤖 **ML-Powered Attack Detection** – Random Forest model with 98.7% accuracy for classifying network attacks
- 🗺️ **Geographic Threat Visualization** – Interactive world map showing real-time attack origins
- 📊 **Comprehensive Analytics** – Attack distribution, timelines, and prediction trends
- 🚨 **Real-Time Alert System** – Instant notifications with severity-based prioritization
- 👥 **Team Collaboration** – Incident case management and team activity tracking
- 📄 **Multi-Format Reports** – Generate and export security reports in CSV and PDF formats

---

## ✨ Features

### 🎯 **Core Monitoring**

| Feature | Description |
|---------|-------------|
| **Key Metrics Cards** | Real-time statistics showing total requests, detected attacks, critical alerts, and active connections |
| **Network Traffic Monitoring** | Live visualization of network traffic with packets/sec, bytes/sec, and throughput analysis |
| **ML Attack Detection** | Random Forest model predicting DoS, Probe, R2L, and U2R attacks with confidence scores |
| **Threat Alert System** | Real-time alert feed with severity levels (Critical, High, Medium, Low) |
| **Attack Distribution** | Interactive pie chart showing proportion of different attack types |
| **Attack Timeline** | 7-day attack frequency visualization with trend analysis |
| **Top Attack Sources** | Ranking of IP addresses generating the most attacks |
| **Risk Score System** | Dynamic risk scoring with time decay and severity classification |
| **Protocol Analysis** | Distribution analysis of network protocols (TCP/UDP/ICMP) |
| **Anomaly Detection** | Real-time detection of unusual patterns including traffic spikes |
| **Security Logs Table** | Paginated, filterable logs with search and export functionality |
| **Security Health Indicator** | Composite health score based on multiple security metrics |
| **Attack Prediction Trends** | ML-based forecasting of future attack patterns |

### 🚀 **Advanced Capabilities**

| Feature | Description |
|---------|-------------|
| **MITRE ATT&CK Framework** | Industry-standard mapping of attacks to tactics and techniques |
| **Threat Intelligence Feeds** | Integration with external threat feeds and IOC matching |
| **Team Collaboration** | Incident case management and team activity tracking |
| **Downloadable Reports** | Multi-format report generation (CSV/PDF) |

---

## 🛠️ Tech Stack

### 🖥️ **Frontend**

| Technology | Purpose |
|------------|---------|
| **HTML5** | Structure and semantics |
| **CSS3** | Styling and responsive design |
| **JavaScript (ES6)** | Interactive functionality |
| **Chart.js 4.4.0** | Data visualization and charts |
| **Leaflet 1.9.4** | Interactive maps |
| **Font Awesome 6** | Icon library |

### ⚙️ **Backend**

| Technology | Purpose |
|------------|---------|
| **Python 3.8+** | Core programming language |
| **Flask 2.3.3** | Web framework and REST API |
| **scikit-learn 1.3.0** | Machine learning model training |
| **pandas 2.0.3** | Data manipulation and analysis |
| **numpy 1.24.3** | Numerical computing |
| **joblib 1.3.2** | Model serialization |
| **reportlab 4.0.9** | PDF report generation |

### 🗄️ **Database**

| Technology | Purpose |
|------------|---------|
| **CSV files** | Lightweight data storage |
| **JSON** | Configuration and mapping |

### ☁️ **Deployment**

| Service | Purpose |
|---------|---------|
| **GitHub** | Source code hosting |
| **Localhost** | Development server |

---

## 🚀 Quick Start

### 🔧 Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (optional)

### 🧩 Installation Steps

1️⃣ **Clone the Repository**
```bash
git clone https://github.com/Asmitha25-as/cyber-attack-detection-dashboard.git
cd cyber-attack-detection-dashboard
```

2️⃣ **Create Virtual Environment**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3️⃣ **Install Dependencies**
```bash
pip install -r requirements.txt
```

4️⃣ **Download Dataset** (if not already present)
```bash
# Create dataset directory
mkdir -p dataset

# Download NSL-KDD training data
curl -o dataset/nsl_kdd.csv https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt
```

5️⃣ **Train the ML Model**
```bash
python train_model.py
```

6️⃣ **Run the Application**
```bash
python app.py
```

7️⃣ **Access the Dashboard**
```
http://localhost:5000
```

---

## 🔐 Environment Variables

Create a `.env` file in the root directory (optional for future enhancements):

```
FLASK_SECRET_KEY=your-secret-key-here
MODEL_PATH=model/random_forest_model.joblib
DATA_PATH=data/
REPORTS_PATH=reports/
```

---

## 📚 API Endpoints

### 🔐 **System**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serve main dashboard |
| GET | `/api/health` | API health check |

### 📊 **Dashboard Data**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/metrics` | Get key metrics |
| GET | `/api/traffic-monitoring` | Get traffic data |
| GET | `/api/alerts` | Get threat alerts |
| GET | `/api/attack-distribution` | Get attack distribution |
| GET | `/api/attack-timeline` | Get timeline data |
| GET | `/api/top-attackers` | Get top attacking IPs |
| GET | `/api/geo-attacks` | Get geographic data |
| GET | `/api/risk-scores` | Get risk scores |
| GET | `/api/protocol-analysis` | Get protocol distribution |
| GET | `/api/anomalies` | Get detected anomalies |
| GET | `/api/security-logs` | Get paginated logs |
| GET | `/api/security-health` | Get health indicators |
| GET | `/api/prediction-trends` | Get attack predictions |

### 🤖 **ML Prediction**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/predict` | ML attack prediction |

### 📄 **Reports**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/generate-report` | Generate security report |
| GET | `/download-report/<filename>` | Download generated report |

---

## 📊 ML Model Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 98.73% |
| **Precision** | 98.71% |
| **Recall** | 98.73% |
| **F1-Score** | 98.34% |

### Attack Classification

| Attack Type | Description | Detection Rate |
|-------------|-------------|----------------|
| **DoS** | Denial of Service attacks | 99.2% |
| **Probe** | Surveillance and scanning | 98.5% |
| **R2L** | Remote to Local access | 97.8% |
| **U2R** | User to Root escalation | 96.3% |
| **Normal** | Benign network traffic | 99.5% |

---

## 📁 Project Structure

```
cyber-attack-detection-dashboard/
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
│   ├── feature_names.json                # Feature names list
│   └── training_history.csv               # Training metrics
│
├── data/                               # Application data
│   ├── predictions_log.csv              # Historical predictions
│   └── alerts_log.csv                    # Active alerts
│
├── dataset/                            # Training dataset
│   └── nsl_kdd.csv                        # NSL-KDD dataset

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

---

## 📞 Contact

**Asmitha**
- GitHub: [@Asmitha25-as](https://github.com/Asmitha25-as)
- Email: asmithangarj25@gmail.com

**Project Link**: [https://github.com/Asmitha25-as/cyber-attack-detection-dashboard](https://github.com/Asmitha25-as/cyber-attack-detection-dashboard)

---

<p align="center">
  <b>Built with 🛡️ for cybersecurity professionals</b>
</p>

