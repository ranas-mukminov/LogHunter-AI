# LogHunter-AI

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![CI](https://github.com/ranas-mukminov/LogHunter-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/ranas-mukminov/LogHunter-AI/actions)

**AI-Powered Threat Hunting That Finds What Rules Miss**

🔗 **Website**: [https://run-as-daemon.dev](https://run-as-daemon.dev)  
👤 **Author**: [Ranas Mukminov (@ranas-mukminov)](https://github.com/ranas-mukminov)

---

## 🎯 Problem Statement

Traditional SIEM systems rely on **signature-based detection** — they can only find threats they already know about. This approach misses:

- ✗ Insider threats using valid credentials
- ✗ APT lateral movement with legitimate tools
- ✗ Slow & low data exfiltration
- ✗ Zero-day exploitation patterns
- ✗ Living-off-the-land (LOLBins) attacks

**LogHunter-AI** uses **unsupervised Machine Learning** to detect behavioral anomalies — catching the "unknown unknowns" that evade traditional rules.

---

## 🚀 Key Capabilities

| Feature | Description |
|---------|-------------|
| 🔍 **Behavioral Anomaly Detection** | Learn normal baselines, detect deviations |
| 🔗 **Attack Chain Correlation** | Connect isolated events into full attack narratives |
| 📡 **Beaconing Detection** | Identify C2 communication through traffic patterns |
| 🧠 **Self-Learning Baselines** | Automatically adapt to your environment |
| 🎯 **MITRE ATT&CK Mapping** | Map anomalies to tactics & techniques |
| ⚡ **High Performance** | Process 10,000+ EPS on a single node |

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DATA SOURCES                            │
│  Windows | Linux | Network | Cloud | Endpoint                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              INGESTION (Kafka, Logstash, Filebeat)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         PREPROCESSING (Parse, Normalize to ECS, Enrich)      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                ML DETECTION ENGINE                           │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│  │ Isolation    │ │ Autoencoder  │ │ LSTM         │         │
│  │ Forest       │ │ Deep NN      │ │ Sequences    │         │
│  └──────────────┘ └──────────────┘ └──────────────┘         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           CORRELATION (Attack Chain Reconstruction)          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         OUTPUT (API, Dashboard, SIEM, Alerts)                │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/ranas-mukminov/LogHunter-AI.git
cd LogHunter-AI
```

### 2. Start Services

```bash
docker-compose up -d
```

### 3. Verify

```bash
curl http://localhost:8000/health
```

That's it! LogHunter-AI is now running and ready to ingest logs.

---

## 📡 Supported Data Sources

| Source Type | Examples | Status |
|-------------|----------|--------|
| **Windows** | Security Event Log, Sysmon, PowerShell | ✅ Supported |
| **Linux** | Auth.log, Auditd, Syslog | ✅ Supported |
| **Network** | Zeek, NetFlow, DNS, Firewall | ✅ Supported |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit | ✅ Supported |
| **Endpoint** | CrowdStrike, Carbon Black, SentinelOne | ✅ Planned |

---

## 🧠 ML Models Explained

### Isolation Forest
- **Use Case**: Point anomalies (single unusual events)
- **Example**: User logs in from unusual country

### Autoencoder (Deep Neural Network)
- **Use Case**: Complex multivariate anomalies
- **Example**: Unusual combination of process + network + user behavior

### LSTM Sequence Detector
- **Use Case**: Sequence anomalies
- **Example**: Unusual command sequences indicating attack chain

### Beaconing Detector
- **Use Case**: C2 communication patterns
- **Example**: Regular callbacks to external IP

---

## 📈 Example Detections

<details>
<summary><b>🎯 Lateral Movement Detection</b></summary>

```
Anomaly Detected: Lateral Movement
Score: 0.92
Entity: user:alice

Timeline:
1. 14:32 - SMB connection to DC01 (unusual for this user)
2. 14:33 - Process: powershell.exe -enc <base64>
3. 14:34 - WMI call to remote host
4. 14:35 - Network connection to internal host never contacted before

MITRE ATT&CK: T1021 (Remote Services)
Recommendation: Investigate user alice, check for credential compromise
```
</details>

<details>
<summary><b>🔴 Data Exfiltration Detection</b></summary>

```
Anomaly Detected: Unusual Data Transfer
Score: 0.88
Entity: host:web-server-03

Analysis:
- Outbound traffic to external IP: 45.67.89.123
- Transfer volume: 2.3GB (10x normal baseline)
- Time: 02:47 AM (outside business hours)
- Port: 443 (HTTPS, but to unknown destination)

MITRE ATT&CK: T1041 (Exfiltration Over C2)
Recommendation: Block connection, investigate compromised host
```
</details>

---

## 🏢 Commercial Support

LogHunter-AI is **Open-Core**. The core anomaly detection engine is free. For enterprise deployments, we offer:

✅ **Distributed Architecture** (10M+ EPS)  
✅ **Custom ML Model Training** on your data  
✅ **Advanced Correlation Rules** engine  
✅ **SOC Workflow Integration**  
✅ **Compliance Reporting** (SOC2, HIPAA, GDPR)  
✅ **24/7 Support with SLA**  
✅ **Threat Hunting as a Service**

📞 **Contact**: [https://run-as-daemon.dev/enterprise](https://run-as-daemon.dev)

---

## 🛠️ Development

### Run Tests

```bash
pytest tests/
```

### Train Baselines

```bash
python scripts/train_baselines.py --entity-type user --lookback 30d
```

### Query Anomalies

```bash
curl "http://localhost:8000/api/v1/anomalies?min_score=0.8&limit=10"
```

---

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [ML Models](docs/ML_MODELS.md)
- [API Reference](docs/API.md)
- [Threat Hunting Guide](docs/HUNTING_GUIDE.md)

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

## 🔒 Security & Privacy

- ✅ All data stays in your infrastructure
- ✅ No external telemetry or analytics
- ✅ GDPR & compliance-friendly
- ✅ Full audit trail

For security issues, contact: security@run-as-daemon.ru

---

**Built with ❤️ by [Ranas Mukminov](https://github.com/ranas-mukminov)**

Star ⭐ this repo if you find it useful!
