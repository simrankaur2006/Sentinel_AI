# 🛡️ SentinelAI — AI-Powered SOC Copilot

**Intelligent Security Monitoring • Anomaly Detection • Incident Analysis**

SentinelAI is an AI-assisted Security Operations Center (SOC) platform that helps security analysts detect suspicious activity, prioritize alerts, and investigate potential security incidents using machine learning and rule-based detection.

It combines a modern React dashboard, a FastAPI backend, PostgreSQL storage, and optional AI-assisted analysis to create a practical cybersecurity monitoring solution.

## ✨ Key Features

- **🔍 Anomaly Detection:** Identify unusual activity using an Isolation Forest machine learning model.
- **⚡ Rule-Based Detection:** Flag suspicious events using configurable detection rules.
- **📂 Security Log Ingestion:** Upload supported log files for analysis.
- **🚨 Alert Prioritization:** Organize detected events by severity and investigation priority.
- **🎯 MITRE ATT&CK Mapping:** Associate supported detection patterns with relevant MITRE ATT&CK tactics and techniques.
- **🤖 AI-Assisted Analysis:** Optional local LLM or API-based analysis for security insights.
- **📋 Incident Reporting:** Generate structured incident reports to support investigation and documentation.
- **🧪 Sample Security Logs:** Use sample data to explore detection workflows locally.
- **🔐 Local-First Setup:** Run the application locally without requiring a paid AI service for its core fallback functionality.

## 🧰 Tech Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn, Isolation Forest |
| Detection | Rule-Based Detection Engine |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| AI Analysis | Local LLM / Optional API |
| API Documentation | FastAPI / OpenAPI |
| Development | Git, GitHub, VS Code |

## 🏗️ System Architecture

```mermaid
flowchart TD
    A[Security Log Upload] --> B[React + Vite Dashboard]
    B --> C[FastAPI Backend]
    C --> D[Log Processing]
    D --> E[Rule-Based Detection]
    D --> F[Isolation Forest]
    E --> G[Alert Correlation and Prioritization]
    F --> G
    G --> H[MITRE ATT&CK Mapping]
    G --> I[Optional AI Analysis]
    G --> J[(PostgreSQL)]
    H --> J
    I --> J
    J --> K[Dashboard and Incident Reports]
```

## 🚀 Getting Started

Follow these steps to set up SentinelAI on your local machine.

### Prerequisites

Install the following:

- Python 3.11 or a compatible version supported by the project dependencies
- Node.js and npm
- PostgreSQL
- Git (optional, for cloning the repository)

### 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SentinelAI
```

Replace the repository URL with your actual GitHub repository URL.

### 2. Configure PostgreSQL

Create a PostgreSQL database and a dedicated user.

Example SQL:

```sql
CREATE USER sentinel WITH PASSWORD 'CHANGE_ME';
CREATE DATABASE sentinelai OWNER sentinel;
```

If you already created the `sentinel` user and `sentinelai` database, do not create them again.

### 3. Configure the Backend

Open a terminal in the backend directory:

```powershell
cd backend
```

Create and activate a virtual environment if you do not already have one:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create or update `backend/.env` using the project's existing environment configuration.

Example:

```env
DATABASE_URL=postgresql://sentinel:CHANGE_ME@localhost:5433/sentinelai
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
MAX_UPLOAD_MB=10
MAX_UPLOAD_ROWS=50000
LOG_LEVEL=INFO
AI_PROVIDER=fallback
```

**Configuration notes:**

- Replace `CHANGE_ME` with your actual PostgreSQL password.
- Use the PostgreSQL port configured on your machine. The example uses `5433`.
- Keep `.env` private and never commit passwords or API keys.
- The fallback AI provider is intended to support operation without an external AI API. Optional AI integrations may require additional configuration.

### 4. Initialize the Database

Run these commands from the `backend` directory:

```powershell
python -m scripts.init_db
python -m scripts.seed_demo
```

The initialization script prepares the database tables. The demo seeding script loads sample data if supported by the current project configuration.

### 5. Start the Backend

From the `backend` directory, run:

```powershell
uvicorn app.main:app --reload
```

The backend should be available at:

- API: `http://127.0.0.1:8000`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

### 6. Start the Frontend

Open a **second terminal** at the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, commonly:

`http://localhost:5173`

Keep both terminals running while using the application.

## 📁 Project Structure

```text
SentinelAI/
├── backend/
│   ├── app/
│   │   ├── db/
│   │   ├── ...
│   ├── scripts/
│   │   ├── init_db.py
│   │   └── seed_demo.py
│   ├── sample_data/
│   ├── tests/
│   ├── .env
│   └── requirements.txt
├── frontend/
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── docs/
├── reports/
├── SECURITY.md
└── README.md
```

The tree above is a simplified overview. Refer to the actual repository for the complete module structure.

## 🔄 How It Works

1. **Ingest:** The user uploads supported security logs or works with sample data.
2. **Process:** The backend validates and processes incoming events.
3. **Detect:** Rule-based logic and the Isolation Forest model identify potentially suspicious behavior.
4. **Prioritize:** Detected events are organized for further investigation.
5. **Enrich:** Supported detections can be associated with MITRE ATT&CK techniques.
6. **Analyze:** Optional AI analysis can assist with interpreting findings.
7. **Report:** Relevant results are stored and presented for security investigation and reporting.

## 🔒 Security and Privacy

- Designed for local development and testing.
- Keep database credentials and API keys in environment variables.
- Use authorized security logs and datasets only.
- Review generated findings before treating them as confirmed incidents.
- Detection results are indicators for investigation, not guarantees that an event is malicious.
- Production deployment requires additional security hardening and testing.

## 🧪 Testing

Run backend tests from the `backend` directory:

```powershell
python -m pytest
```

Use the project's supported test suite and sample data to validate detection behavior.

## 🛣️ Future Enhancements

- Real-time log ingestion and streaming detection
- Advanced alert correlation and deduplication
- Expanded MITRE ATT&CK coverage
- Role-based access control and audit trails
- Model evaluation and detection-performance metrics
- Docker-based deployment and CI/CD integration

## 🎯 Project Objective

The objective of SentinelAI is to explore how machine learning, rule-based security analytics, and optional LLM-assisted investigation can improve security monitoring workflows and reduce manual effort in SOC operations.

## 👩‍💻 Author

**Simran Kaur**

GitHub: [@simrankaur2006](https://github.com/simrankaur2006)

## 📄 License

See the repository's `LICENSE` file for applicable licensing terms.
