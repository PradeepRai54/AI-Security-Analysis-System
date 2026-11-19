# 🛡️ AI Security Analysis System

An intelligent security analysis application that combines Machine Learning, rule-based risk assessment and VirusTotal threat intelligence to identify suspicious SMS messages, potentially malicious URLs and unsafe files.

## 📌 Project Overview

The **AI Security Analysis System** is a Python-based security application developed using Streamlit. It provides multiple security analysis capabilities through a unified interface.

The system combines a trained Machine Learning model for SMS spam classification with VirusTotal API integration for URL and file threat analysis.

## ✨ Key Features

### 1. SMS Spam Detection

- Machine Learning-based SMS classification.
- Classifies messages as Spam or Not Spam.
- TF-IDF feature extraction using word and character n-grams.
- Logistic Regression classification model.
- Optimized classification threshold.

### 2. Intelligent Risk Analysis

- Rule-based suspicious keyword detection.
- Financial and payment-related keyword identification.
- Credential and OTP-related detection indicators.
- Suspicious delivery and parcel message detection.
- Risk scoring from 0–100.
- Risk levels: Low, Moderate, High and Critical.

### 3. URL Threat Scanner

- URL submission to VirusTotal.
- External threat intelligence analysis.
- Malicious and suspicious detection counts.
- Analysis status and detection ratio.
- Individual antivirus engine results when available.

### 4. File Malware Scanner

- File upload for VirusTotal analysis.
- SHA-256 hash calculation.
- Malware detection results.
- Antivirus engine analysis.
- File analysis status and detection ratio.

### 5. Security Recommendations

- Explanation of suspicious indicators.
- Safety recommendations based on risk level.
- Warnings about suspicious links and sensitive information.

### 6. Dashboard and Reporting

- Analysis dashboard.
- Analysis history using SQLite.
- Model performance evaluation.
- Confusion matrix and classification metrics.

## 🏗️ System Architecture

```text
                USER INPUT
                    |
          +---------+---------+
          |         |         |
         SMS       URL       FILE
          |         |         |
          v         v         v
       MACHINE   VIRUSTOTAL VIRUSTOTAL
       LEARNING     API       API
          |         |         |
          v         v         v
       SPAM      URL THREAT  FILE THREAT
       ANALYSIS  ANALYSIS    ANALYSIS
          |         |         |
          +---------+---------+
                    |
                    v
          AI SECURITY ANALYSIS
                 SYSTEM
                    |
                    v
           STREAMLIT INTERFACE
                    |
          +---------+---------+
          |         |         |
       RESULTS   HISTORY   DASHBOARD
```

## 🧰 Technologies Used

| Technology          | Purpose                          |
| ------------------- | -------------------------------- |
| Python              | Main programming language        |
| Streamlit           | Web application interface        |
| Pandas              | Dataset handling                 |
| NumPy               | Numerical operations             |
| Scikit-learn        | Machine Learning                 |
| TF-IDF              | Text feature extraction          |
| Logistic Regression | SMS classification               |
| NLTK                | Text preprocessing               |
| SQLite              | Analysis history storage         |
| VirusTotal API v3   | URL and file threat intelligence |
| Requests            | API communication                |
| Pickle              | Saving trained ML models         |

## 🤖 Machine Learning Model

The project uses the SMS Spam Collection dataset.

### Dataset Information

| Category | Messages |
| -------- | -------: |
| Not Spam |    4,516 |
| Spam     |      653 |
| Total    |    5,169 |

### Model Configuration

- Algorithm: Logistic Regression
- Feature extraction: TF-IDF
- Word n-grams: Unigrams and Bigrams
- Character n-grams: 3–5
- Class weighting: Balanced
- Training/Validation/Testing split: 70% / 15% / 15%
- Optimized decision threshold: Approximately 0.4777

### Model Evaluation Results

The improved model achieved the following results on its held-out test dataset:

| Evaluation Metric |  Score |
| ----------------- | -----: |
| Accuracy          | 98.32% |
| Spam Precision    | 94.74% |
| Spam Recall       | 91.84% |
| Spam F1-Score     | 93.26% |

### Confusion Matrix

| Actual / Predicted | Not Spam | Spam |
| ------------------ | -------: | ---: |
| Not Spam           |      672 |    5 |
| Spam               |        8 |   90 |

These results represent the recorded evaluation of the trained model on the test split. They do not guarantee equivalent performance on new messages or other scam categories.

## 📂 Project Structure

```text
AI_Scam_Detection_System/
│
├── app.py
├── analyzer.py
├── vt_scanner.py
├── database.py
├── train_model.py
├── preprocessing.py
│
├── spam.csv
│
├── spam_model_improved.pkl
├── label_encoder_improved.pkl
├── model_threshold.pkl
├── model_results.pkl
│
├── requirements.txt
├── .gitignore
│
└── .streamlit/
    └── secrets.toml
```

**Note:** `secrets.toml` is a local configuration file and must not be committed to GitHub.

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-Security-Analysis-System.git
```

### 2. Navigate to the project directory

```bash
cd AI-Security-Analysis-System
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

Windows:

```powershell
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Download NLTK resources

If they are not already installed, run:

```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

### 7. Configure VirusTotal API

Create a free account at:

https://www.virustotal.com/gui/join-us

Obtain your API key from your VirusTotal account.

Create a folder named `.streamlit` in the project directory.

Inside it, create `secrets.toml`:

```toml
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

Replace the placeholder with your actual API key.

**Security:** Never upload your API key to GitHub or share it publicly.

### 8. Run the application

```bash
python -m streamlit run app.py
```

The application will open in your browser.

## 🔑 VirusTotal API Integration

The system uses VirusTotal API v3 for external URL and file threat intelligence.

The integration supports:

- URL submission.
- File submission.
- SHA-256 hash calculation.
- Analysis ID generation.
- Analysis report retrieval.
- Malicious, suspicious, harmless and undetected counts.
- Individual antivirus engine results when available.

VirusTotal analysis is asynchronous. A submitted scan may initially show a queued or pending status.

Official documentation:

https://docs.virustotal.com/reference/overview

**Privacy warning:** Submitted URLs and files may be shared with VirusTotal's security community. Do not submit confidential or sensitive files.

## 📊 Application Modules

| Module               | Description                 |
| -------------------- | --------------------------- |
| Message Analyzer     | SMS spam and risk analysis  |
| URL Threat Scanner   | URL security analysis       |
| File Malware Scanner | Uploaded file analysis      |
| Dashboard            | Application overview        |
| Analysis History     | Stored SMS analysis history |
| Model Performance    | ML evaluation metrics       |
| About Project        | Project information         |

## ⚠️ Limitations

- SMS classification depends on the quality and coverage of the training dataset.
- Rule-based risk scores are heuristic assessments, not probabilities of fraud.
- VirusTotal results depend on available security engines.
- A clean VirusTotal report does not guarantee that a URL or file is safe.
- VirusTotal API usage is subject to account limits and permissions.
- The current file scanner uses the standard VirusTotal upload endpoint with a 32 MB limit.

## 🚀 Future Enhancements

- Detailed security intelligence dashboard.
- Enhanced phishing detection.
- More comprehensive malicious URL analysis.
- Improved threat classification.
- Advanced reporting and visualization.
- Expanded security datasets.

## 👨‍💻 Author

**Pradeep Rai**

BCA Student | Machine Learning | Python | Cybersecurity

## 📜 Disclaimer

This project is developed for educational and security research purposes. It is intended to assist with identifying suspicious messages, URLs and files. It should not be treated as a replacement for professional antivirus software or security investigation.

---

**Project:** AI Security Analysis System  
**Category:** Machine Learning | Cybersecurity | Threat Intelligence  
**Interface:** Streamlit  
**Language:** Python
