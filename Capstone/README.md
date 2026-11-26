# DarkWatch: Leaked Credential Intelligence & Dark Web Monitoring System

**Project Title:** Design of a Dark Web Monitoring and Leaked Credential Intelligence System for Ethical Threat Research  
**Application Name:** DarkWatch  
**Target Environment:** College Capstone Project / Academic Defense Demonstration  
**License / Policy:** Ethical Threat Research & Synthetic Intelligence Only  

---

## 1. Project Overview
**DarkWatch** is an ethical threat intelligence platform designed to ingest, process, and analyze leaked credential feeds and breach dumps. It provides defensive cybersecurity analysts with proactive visibility into compromised identities, credential exposure severity, and domain-wide risks—while adhering strictly to ethical guidelines and privacy principles (sensitive passwords are never exposed, and emails are masked).

### Key Highlights
- **Administrator Authentication:** Secure session-based login page with password hashing (`werkzeug.security`) and brute-force audit logging.
- **Persistent Notification System:** Real-time top navigation bell icon with badge counter, dropdown notification center, mark-as-read, and clear-all capabilities stored in SQLite.
- **Clean Cybersecurity UI:** Built with a dark navy & charcoal visual theme and subtle blue accents.
- **Five Dedicated Navigation Modules:**
  1. **Dashboard:** High-level executive statistics (Total Records Analysed, Leaked Credentials, High Risk Records, Last Scan), Recent Scans table, and Risk Distribution Chart.
  2. **Credential Analysis:** Drag-and-drop file ingestion (CSV and TXT breach dumps), automated credential parsing, regex email detection, duplicate checking, and severity classification.
  3. **Leak Records:** Comprehensive, paginated record repository with dynamic searching, severity filtering (High, Medium, Low), and status tracking (`Active Threat`, `Investigating`, `Remediated`).
  4. **Risk Assessment:** Dynamic overall risk score calculation (0–100 scale), severity count breakdown, vulnerability factor analytics, and an executive threat assessment summary.
  5. **Settings:** Theme toggling (Dark Navy, Charcoal Dark, Slate Cyber), application customization, database reset, and synthetic sample data seeding.
- **Ethical Research Compliance:** Operates entirely on synthetic test datasets. No real passwords stored; all emails sanitized and masked.

---

## 2. Administrator Credentials (Development & Demonstration)

| Parameter | Value |
|---|---|
| **Role** | System Administrator |
| **Username** | `Admin` |
| **Password** | `Admin@123` |

> Passwords are encrypted using modern cryptographic hashing algorithms in SQLite. The dashboard and all analytical endpoints require an active authenticated session.

---

## 3. Directory Structure

```text
DarkWatch/
│
├── backend/                       # Python Flask REST API
│   ├── app.py                     # Main Flask server, Auth routes & Protected APIs
│   ├── database.py                # SQLite database ORM (Users, Sessions, Notifications, Scans)
│   ├── analyzer.py                # Credential ingestion & risk heuristics engine
│   ├── sample_data.py             # Synthetic threat intelligence generator
│   ├── requirements.txt           # Python dependencies
│   ├── data/                      # SQLite storage (darkwatch.db)
│   └── uploads/                   # Temporary upload directory
│
├── frontend/                      # Web Single Page Application (SPA)
│   ├── index.html                 # Login screen & Dashboard Layout (Top Nav, Sidebar, 5 Views)
│   ├── server.js                  # Lightweight local Node.js static server
│   ├── package.json               # Frontend start script
│   ├── css/
│   │   └── styles.css             # Dark navy, charcoal theme, login & notification styles
│   ├── js/
│   │   ├── app.js                 # UI controllers, auth state, notification center, view router
│   │   ├── api.js                 # API client with session credential handling
│   │   └── charts.js              # Doughnut & Bar charts with offline fallback
│   └── assets/                    # Static icons and assets
│
├── datasets/                      # 6 Dedicated Evaluation Datasets
│   ├── dataset_01_low_risk.csv            # 20 records (Low severity, modern salted hashes)
│   ├── dataset_02_medium_risk.csv         # 30 records (Medium severity, weak MD5/SHA-1 hashes)
│   ├── dataset_03_high_risk.csv           # 30 records (High severity, admin accounts, weak passwords)
│   ├── dataset_04_mixed_credentials.csv   # 50 records (Balanced distribution across all tiers)
│   ├── dataset_05_duplicate_records.csv   # 30 records (Repeated emails to test duplicate detection)
│   └── dataset_06_large_sample.csv        # 100 records (Full volume stress-testing dataset)
│
├── sample_datasets/               # Ready-to-use synthetic test files
│   ├── synthetic_darkweb_leaks_sample.csv
│   ├── synthetic_pastebin_dump_sample.txt
│   └── synthetic_corporate_breach.csv
│
└── README.md                      # Comprehensive project documentation
```

---

## 4. Installation & Setup

### Step 1: Open a Terminal & Navigate to Project
```powershell
cd "c:\Users\THARUNIKA REDDY\OneDrive\Documents\Ethical Hacking Cap\DarkWatch"
```

### Step 2: Install Backend Dependencies
Navigate to `backend` folder and install Python requirements:
```powershell
cd backend
pip install -r requirements.txt
```

*(Packages installed: `Flask`, `flask-cors`, `pandas`, `werkzeug`)*

---

## 5. Running the Application

### Terminal 1 — Start the Backend Server (Port 5000)
```powershell
cd "c:\Users\THARUNIKA REDDY\OneDrive\Documents\Ethical Hacking Cap\DarkWatch\backend"
python app.py
```
> The backend will start on **`http://127.0.0.1:5000`**.  
> Automatically initializes `darkwatch.db`, seeds the default admin user (`admin` / `Admin@123`), and prepares the notification tables.

---

### Terminal 2 — Start the Frontend Server (Port 3000)
Open a second terminal window:
```powershell
cd "c:\Users\THARUNIKA REDDY\OneDrive\Documents\Ethical Hacking Cap\DarkWatch\frontend"
npm start
```
*(Alternative without Node: `python -m http.server 3000` inside `DarkWatch/frontend`)*

> Open your web browser and navigate to:  
> **`http://localhost:3000`**

---

## 6. How to Demonstrate for Your Capstone Evaluation (Viva Walkthrough)

Follow these steps during your project presentation:

1. **Administrator Login Demonstration:**
   - Open **`http://localhost:3000`**. Notice that the Login page appears first; the dashboard cannot be accessed unauthenticated.
   - Enter an incorrect password to demonstrate security validation and error message display.
   - Enter the valid credentials (`Admin` / `Admin@123`).
   - Use the **Show/Hide password** eye toggle button.
   - Click **Sign In**. Observe the success message and immediate redirection to the Dashboard.

2. **Notification System Demonstration:**
   - Notice the **Notification Bell** icon in the top right corner.
   - Point out the red unread badge indicator.
   - Click the bell to open the **Notification Dropdown**.
   - Show recent events automatically logged:
     - *"Login Successful"*
     - *"Failed Login Attempt"* (from the invalid attempt earlier)
     - *"Dataset Uploaded"* / *"Analysis Completed"*
   - Demonstrate marking individual notifications as read or clicking **"Mark all as read"** and **"Clear All"**.

3. **Dashboard Walkthrough:**
   - Review the 4 summary metrics: Total Records, Leaked Credentials, High Risk Records, and Last Scan.
   - Point out the **Risk Distribution Doughnut Chart** and the **Recent Activity** table listing previous breach ingestions.

4. **Credential Ingestion & Analysis:**
   - Click **Credential Analysis** in the left sidebar.
   - Click **Browse Local File** and select one of the provided files from `DarkWatch/sample_datasets/` (or click **Load Synthetic Sample**).
   - Click **Analyse Records**.
   - Show how the backend dynamically extracts valid emails, calculates duplicate entries, flags high-risk privileged accounts, and visualizes the severity breakdown bar.
   - Point out the new notifications generated in the notification center: *"Dataset Uploaded"*, *"Analysis Completed"*, and *"High-Risk Threat Detected"*.

5. **Leak Records Repository:**
   - Click **Leak Records** in the sidebar.
   - Demonstrate search and filtering (by risk level or status).
   - Emphasize that actual passwords are **masked** (`••••••••`) to comply with ethical threat intelligence standards.

6. **Risk Assessment:**
   - Click **Risk Assessment** in the sidebar.
   - Explain the calculated **Overall Risk Score** (0–100 weighted formula based on severity and exposure patterns).
   - Review the dynamic **Executive Assessment Summary** bullets.

7. **Settings & Data Reset Demonstration:**
   - Click **Settings** in the sidebar.
   - View the **Account Settings** (admin username, password change).
   - Toggle notification preferences and session timeout.
   - Test the **Appearance** dark/light theme switch.
   - Scroll to the **Data Reset** section at the bottom.
   - Click **Reset Data** to trigger the confirmation modal: *"Are you sure you want to reset all application data? This action cannot be undone."*
   - Click **Confirm Reset** and demonstrate how the dashboard metrics reset to zero, analysis history clears, and a success notification is shown while preserving credentials and the `datasets/` folder.

8. **Logout & Session Termination:**
   - Click the **Administrator Profile** in the top right corner.
   - Click **Logout**.
   - Verify that the session is invalidated and the application immediately returns to the Login page.

---

## 7. Ethical Research & Academic Disclaimer
DarkWatch was engineered strictly for academic demonstration and defensive research purposes.  
- It **does not** access unauthorized networks or underground forums.  
- It **does not** acquire or trade stolen credential databases.  
- It relies entirely on generated synthetic data simulating known compromise patterns to facilitate defensive security training.
