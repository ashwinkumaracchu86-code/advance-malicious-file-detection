# Advanced Malicious File Detection System

A comprehensive, real-time cybersecurity web application for detecting malicious files through static analysis, YARA pattern matching, reputation checking, and risk scoring.

## Features

- **User Authentication** — JWT-based auth with admin/user roles, secure password hashing
- **File Upload Scanner** — Drag-and-drop, multi-file upload with progress tracking
- **Static File Analysis** — Hash calculation (MD5, SHA-1, SHA-256), entropy analysis, MIME detection, suspicious string detection
- **YARA Detection** — Pattern-based malware detection with custom educational rules
- **Risk Scoring** — 0-100 scoring engine with Safe/Suspicious/Malicious classification
- **VirusTotal Integration** — Optional hash reputation checking via VT API
- **Quarantine System** — Isolate suspicious files with admin review and restore/delete
- **USB Scanner** — Detect and scan removable drives (web-based demo)
- **Folder Monitoring** — Real-time file system monitoring with auto-scan
- **Scan History** — Full history with search, filter, sort, and pagination
- **Security Dashboard** — Live stats, charts, recent scans, and threat overview
- **Detailed Reports** — Complete file analysis with PDF export
- **Alert System** — In-app notifications and optional email alerts
- **Audit Logs** — Complete activity logging for compliance
- **Machine Learning** — Optional ML-based detection module

## Architecture

```
┌─────────────────┐     HTTP/REST     ┌─────────────────┐     ORM      ┌─────────────┐
│                  │ ◄──────────────► │                  │ ◄──────────► │              │
│   React + Vite   │                   │   FastAPI        │              │   SQLite     │
│   Tailwind CSS   │                   │   Python 3.11    │              │   Database   │
│   Recharts       │                   │   SQLAlchemy     │              │              │
│                  │                   │   Uvicorn        │              │              │
└─────────────────┘                   └─────────────────┘              └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  Scanner Engine   │
                                    │  YARA Rules       │
                                    │  Risk Scorer      │
                                    │  VT Integration   │
                                    └─────────────────┘
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS, Recharts, React Icons |
| Backend | Python 3.11, FastAPI, SQLAlchemy, Pydantic |
| Database | SQLite |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Analysis | YARA-python, python-magic, hashlib |
| Reports | FPDF2 |
| Testing | pytest, FastAPI TestClient |

## Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- npm or yarn

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/malicious-file-detection.git
cd malicious-file-detection
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

### 3. Frontend Setup

```bash
cd frontend
npm install
```

### 4. Database Setup

The database is created automatically on first run. No manual setup needed.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SQLite connection string | `sqlite:///./malicious_detection.db` |
| `SECRET_KEY` | Secret key for application | Auto-generated if empty |
| `JWT_SECRET` | Secret key for JWT tokens | `dev-secret-key-change-in-production` |
| `ENCRYPTION_KEY` | Key for encrypting sensitive data | Derived from SECRET_KEY |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:5173` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT token expiry (minutes) | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiry (days) | `7` |
| `MAX_LOGIN_ATTEMPTS` | Failed attempts before lockout | `5` |
| `LOCKOUT_MINUTES` | Lockout duration | `15` |
| `LOGIN_WINDOW_MINUTES` | Failed attempts window | `5` |
| `MAX_UPLOAD_SIZE_MB` | Max file upload size | `50` |
| `ADMIN_USERNAME` | Default admin username | `admin` |
| `ADMIN_EMAIL` | Default admin email | `admin@example.com` |
| `ADMIN_PASSWORD` | Default admin password | Auto-generated if empty |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (optional) | (empty - disabled) |
| `SMTP_HOST` | SMTP server host (optional) | (empty) |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username (optional) | (empty) |
| `SMTP_PASS` | SMTP password (optional) | (empty) |
| `MONITOR_FOLDER` | Default folder to monitor | (empty) |

## Running the Application

### Start Backend

```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Start Frontend

```bash
cd frontend
npm run dev
```

The application will be available at:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Default Admin Credentials

- **Username:** admin (configurable via `ADMIN_USERNAME`)
- **Password:** Auto-generated if `ADMIN_PASSWORD` is not set (check server logs)
- **Email:** admin@example.com (configurable via `ADMIN_EMAIL`)

> **Important:** Set `ADMIN_PASSWORD` in your `.env` file for a known password, or save the auto-generated password from the server logs.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | User login |
| POST | `/auth/register` | User registration |
| GET | `/auth/me` | Current user info |
| POST | `/files/upload` | Upload file(s) |
| GET | `/files` | List files |
| GET | `/files/{id}` | File details |
| POST | `/scan/{file_id}` | Trigger scan |
| GET | `/scan/{scan_id}` | Scan result |
| GET | `/scans` | List all scans |
| GET | `/dashboard/statistics` | Dashboard stats |
| POST | `/quarantine/{file_id}` | Quarantine file |
| GET | `/quarantine` | List quarantined |
| POST | `/quarantine/{id}/restore` | Restore file |
| DELETE | `/quarantine/{id}` | Delete file |
| GET | `/reports/{scan_id}` | Generate PDF |
| GET | `/logs` | Audit logs |

## Testing

```bash
cd tests
pip install pytest
pytest test_backend.py -v
```

## Security Features

- Never executes uploaded files (static analysis only)
- Path traversal prevention
- Filename sanitization
- JWT authentication on protected routes with refresh token support
- Admin-only access for sensitive operations
- Secure file storage outside public directories
- Password hashing with bcrypt
- **Password strength validation** (8+ chars, uppercase, lowercase, digit, special char)
- **Account lockout** after failed login attempts (configurable)
- **Rate limiting** middleware (configurable requests per minute)
- **Security headers** (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, CSP)
- **Request logging** for security auditing
- **File upload size limits** (configurable, default 50MB)
- **File type restrictions** (blocks dangerous extensions like .exe, .bat, .ps1)
- **CORS configuration** with restricted origins
- **WebSocket authentication** via JWT token
- **Sensitive data encryption** for stored credentials
- **Auto-generated admin password** if ADMIN_PASSWORD not set
- **Secret key validation** on startup with warnings
- **Audit logging** for all authentication events
- Input validation via Pydantic

## Project Structure

```
malicious-file-detection/
├── frontend/                 # React + Vite application
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── pages/            # Page components
│   │   ├── services/         # API service layer
│   │   ├── context/          # React context (auth)
│   │   └── App.jsx           # Main app with routing
│   ├── package.json
│   └── vite.config.js
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── main.py           # FastAPI entry point
│   │   ├── database.py       # SQLAlchemy setup
│   │   ├── models/           # Database models
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── routes/           # API routes
│   │   ├── services/         # Business logic
│   │   ├── scanner/          # File analysis engine
│   │   ├── security/         # Auth & JWT
│   │   ├── utils/            # Helper functions
│   │   └── yara_rules/       # YARA detection rules
│   ├── requirements.txt
│   └── .env.example
├── quarantine/               # Isolated file storage
├── uploads/                  # Uploaded file storage
├── reports/                  # Generated PDF reports
├── tests/                    # Test suite
├── docker-compose.yml
└── README.md
```

## Known Limitations

- USB scanning is simulated in the web interface (requires desktop app for full functionality)
- Folder monitoring uses polling (can be enhanced with OS-level watchers)
- ML module requires training data for production use
- VirusTotal integration requires a valid API key

## Future Improvements

- Real-time WebSocket notifications
- Docker containerization
- Multi-user role management
- Cloud storage integration
- Advanced ML models (CNN for binary analysis)
- Plugin system for custom scanners
- Email notification templates
- Export reports in multiple formats

## License

MIT License - For educational and cybersecurity demonstration purposes.
# -advance-malicious-file-detection
"# Advance-malicious-file-detection" 
