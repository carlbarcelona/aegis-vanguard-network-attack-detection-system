# 🛡️ Aegis Vanguard — Machine Learning-Based Intrusion Detection System (IDS)

A real-time Intrusion Detection System that captures live network traffic, extracts flow-based features, and classifies them using Machine Learning.


## 🚀 Overview

This project implements a simplified IDS pipeline:

```
tcpdump → PCAP → CICFlowMeter → CSV → Preprocessing → ML → Prediction
```

### 🔍 What it does

* Captures live network traffic (5-second windows)
* Converts packets into flow-based features (CICFlowMeter format)
* Cleans and aligns features
* Runs:

  * **Layer 1:** Binary classification (BENIGN vs ATTACK)
  * **Layer 2:** Multi-class attack classification
* Outputs predictions per flow


## 📁 Project Structure

```
aegis-vanguard-network-attack-detection-system/
│
├── app/
│   ├── main.py
│   ├── config.py
│
├── data_pipeline/
│   ├── packet_capture.py
│   ├── cicflowmeter
│   ├── data_preprocessor.py
│
├── models/
│   ├── layer1_xgb_pipeline.pkl
│   ├── layer2_rf_smote_pipeline.pkl
│
├── packets_captured/
├── converted_flows/
├── .env
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation Guide


### 1. Clone the Repository

```
git clone https://github.com/carlbarcelona/aegis-vanguard-network-attack-detection-system.git
cd aegis-vanguard-network-attack-detection-system
```

---

### 2. Create Virtual Environment

```
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```

---

### 3. Install Dependencies

```
pip install -r requirements.txt
```

---

## 🌐 Install tcpdump (Linux)

```
# If you're using Kali Linux, skip this step
sudo apt update
sudo apt install tcpdump
```

### 🔐 Fix Permission Issue

```
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

## 📦 Install CICFlowMeter (Python Version — Recommended)

Instead of the Java version, this project uses a modern Python-based CICFlowMeter.

```
cd data_pipeline
pip install cicflowmeter
cd ..
pip install -e ./data_pipeline/cicflowmeter
```

---

### 🧪 Local Test Pipeline

```
python data_pipeline.packet_capture.py
```

This will:

1. Capture traffic
2. Convert PCAP → CSV
3. Preprocess data

---

### 🧠 Run Full IDS (with ML)

```
python app.main.py
```

## 🔄 Pipeline Flow Explained

### 1. Capture

```
tcpdump -i eth0 -G 5 -W 1 -w traffic.pcap
```

* Captures 5 seconds of traffic
* Saves to `.pcap`


### 2. Convert

```
cicflowmeter -f traffic.pcap -c flows.csv
```

* Extracts ~80 flow-based features

### 3. Preprocess

* Removes unnecessary columns
* Handles NaN / infinite values
* Aligns features with trained model

### 4. Predict

* Binary classification
* If ATTACK → multi-class classification


## 📊 Example Output

```
Flow 0: BENIGN
Flow 1: BENIGN
Flow 2: DDoS
```

## 🚀 Future Improvements

* FastAPI integration (API-based IDS)
* Real-time streaming (no PCAP/CSV)
* Dashboard visualization
* Alert system (email / logs)
* Multi-machine monitoring


## 📌 Notes

* This is a **prototype IDS**, not production-ready
* Works best in controlled environments
* Designed for learning ML + networking integration

## 🤝 Contributing

Feel free to fork, improve, and experiment.

## 📜 License

MIT License

## 🙌 Acknowledgment

Inspired by CICIDS2017 dataset and flow-based intrusion detection techniques.
