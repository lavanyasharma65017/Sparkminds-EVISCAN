# 🔍 EVI SCAN - AI-Powered Digital Forensics Tool

<div align="center">

![Version](https://img.shields.io/badge/version-3.2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**A comprehensive web-based forensic analysis system for analyzing UFDR (Unified Forensic Data Records) files with natural language querying, scenario detection, and AI-powered insights.**

[Features](#-features) • [Quick Start](#-quick-start) • [Installation Guide](#-complete-installation-guide) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🌟 Features

### ✅ Core Forensic Analysis
- **Scenario Detection**: Ships with three reference scenarios (Insider Data Leak, Scam Network, SIM Swap Attack) but the engine can analyze **any case** as long as the UFDR data is structured correctly
- **Natural Language Queries**: Ask questions in plain English
- **Keyword Recognition**: Comprehensive keyword matching across all UFDR data
- **Pattern Matching**: Financial, suspicious, and time-based pattern detection
- **Entity Recognition**: Identifies key people, organizations, and phone numbers
- **Relevance Scoring**: Results ranked by importance and relevance
- **ZIP File Support**: Upload and analyze ZIP UFDR files (standard format) with automatic extraction
- **Adaptive Response System**: Smart query handling that adjusts response style based on query complexity

### 🤖 AI-Powered Features
- **AI Chat Assistant**: Conversational AI for forensic investigation (requires LM Studio)
- **Enhanced Analysis**: AI-generated summaries and insights
- **Semantic Search**: Intelligent data retrieval using keyword-based extraction
- **Direct JSON Extraction**: LLM can directly extract data from JSON files
- **Query Complexity Detection**: Automatically detects query complexity and adjusts response style
- **Context-Aware Processing**: Smart context truncation to fit model's token limits

### 🌐 Web Interface
- **Modern UI**: Clean, responsive web interface with dark/light mode
- **Real-time Analysis**: Instant scenario detection and analysis
- **Interactive Queries**: Natural language query interface
- **File Upload**: Support for UFDR JSON and ZIP file uploads
- **Results Visualization**: Clear display of analysis results with relevance scores
- **Case Management**: Organize and manage multiple forensic cases with status tracking
- **Session Persistence**: Save and restore analysis sessions with chat history
- **PDF Export**: Generate comprehensive PDF reports of analysis results
- **Authentication System**: Secure login/signup with optional development mode bypass
- **Dynamic Smart Analysis**: Enhanced exploration with contact name resolution
- **Image Analysis**: Face and object detection with frequency analysis (see Image Model section)

### 📸 Image Model Features
- **Face Detection**: Detect and identify faces in images using DeepFace
- **Object Detection**: Detect objects using YOLOv8 (person, car, dog, etc.)
- **Combined Detection**: Detect both faces and objects in the same image
- **Frequency Analysis**: 
  - Total appearances, unique images, unique users
  - Per-person frequency statistics
  - Per-object frequency statistics
  - Face and object statistics breakdown
- **Contact Resolution**: Automatic phone number to contact name resolution
- **Upload Support**: Single file or folder upload (completely independent from UFDR)
- **Similarity Search**: Search for similar faces and objects across the dataset
- **Match Details**: Detailed match information with confidence scores

---

## 📚 Project Documentation

> **📖 For comprehensive project details, architecture, data flow, component analysis, and technical deep-dive, please see [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md)**

The PROJECT_ANALYSIS.md file contains:
- Complete project architecture and component breakdown
- Detailed data flow diagrams
- UFDR data structure specifications
- Engine and module documentation
- API endpoint reference
- Database schema details
- Technology stack deep-dive
- Design decisions and rationale

---

## ⚡ Quick Start - Installation Guide for Beginners

> 📦 **Never used Python or Git before?** Don't worry! This guide will walk you through everything step-by-step.

### 📋 What You Need Before Starting

Before installing EVI-SCAN, you need these three things:

1. **Python** (a programming language) - [Download Here](https://www.python.org/downloads/)
2. **Git** (to download the code) - [Download Here](https://git-scm.com/downloads)
3. **LM Studio** (for AI features) - [Download Here](https://lmstudio.ai/) - *We'll install this later*

---

## 🚀 Complete Installation Guide (Step-by-Step)

### Step 1: Install Python (If You Don't Have It)

#### For Windows:
1. Go to https://www.python.org/downloads/
2. Click the big yellow "Download Python" button
3. Run the downloaded installer (`.exe` file)
4. ⚠️ **IMPORTANT**: Check the box that says **"Add Python to PATH"** at the bottom
5. Click "Install Now"
6. Wait for installation to complete
7. Click "Close"

**Verify Python is installed:**
- Open Command Prompt (Press `Windows Key + R`, type `cmd`, press Enter)
- Type: `python --version`
- You should see something like: `Python 3.11.x`
- If you see an error, Python is not installed correctly - try reinstalling

#### For Mac:
1. Python usually comes pre-installed
2. Open Terminal (Press `Cmd + Space`, type "Terminal")
3. Type: `python3 --version`
4. If you see a version number, you're good!
5. If not, install from https://www.python.org/downloads/macos/

#### For Linux:
1. Open Terminal
2. Type: `python3 --version`
3. If not installed, run: `sudo apt-get install python3` (Ubuntu/Debian) or `sudo yum install python3` (CentOS/RHEL)

---

### Step 2: Install Git (If You Don't Have It)

#### For Windows:
1. Go to https://git-scm.com/downloads
2. Click "Download for Windows"
3. Run the installer
4. Click "Next" through all the options (defaults are fine)
5. Click "Install"
6. Wait for installation to complete
7. Click "Finish"

**Verify Git is installed:**
- Open Command Prompt
- Type: `git --version`
- You should see something like: `git version 2.x.x`

#### For Mac:
1. Git usually comes pre-installed
2. Open Terminal
3. Type: `git --version`
4. If you see a version number, you're good!
5. If not, install Xcode Command Line Tools: `xcode-select --install`

#### For Linux:
1. Open Terminal
2. Type: `git --version`
3. If not installed, run: `sudo apt-get install git` (Ubuntu/Debian) or `sudo yum install git` (CentOS/RHEL)

---

### Step 3: Download EVI-SCAN Code

1. **Open Command Prompt (Windows) or Terminal (Mac/Linux)**

2. **Navigate to where you want to save the project** (optional):
   ```bash
   # Windows example: go to Desktop
   cd Desktop
   
   # Mac/Linux example: go to Desktop
   cd ~/Desktop
   ```

3. **Download (clone) the code:**
   ```bash
   git clone https://github.com/debu-devesh/EVI-SCAN.git
   ```

4. **Wait for download to complete** (you'll see "Cloning..." messages)

5. **Navigate into the project folder:**
   ```bash
   cd EVI-SCAN
   cd FORENSIC
   ```

**What just happened?** You downloaded all the code files to your computer!

---

### Step 4: Install Python Packages (Dependencies)

These are additional tools EVI-SCAN needs to work.

**Windows:**
```bash
python scripts/setup_with_lm_studio.py
```

**Mac/Linux:**
```bash
python3 scripts/setup_with_lm_studio.py
```

**What this does:**
- Installs Flask (web server)
- Installs pandas (data processing)
- Installs other required packages
- Takes 2-5 minutes depending on your internet speed

**Expected Output:**
```
🔧 EVI SCAN - Complete Setup (Including AI Chat)
======================================================================
Step 1: Checking Python packages...
----------------------------------------------------------------------
✅ flask is already installed
Installing pandas...
✅ pandas installed successfully
...
✅ All Python packages are installed!
```

**If you see errors:**
- Make sure Python is installed correctly (Step 1)
- Try: `python -m pip install --upgrade pip` first
- Then run the setup script again

---

### Step 5: Install LM Studio (For AI Chat Feature)

> **Note:** You can skip this step if you don't need the AI Chat Assistant feature. The rest of EVI-SCAN will work without it.

#### 5.1 Download LM Studio

1. Go to https://lmstudio.ai/
2. Click "Download" for your operating system
3. Run the installer
4. Follow the installation wizard (defaults are fine)
5. Launch LM Studio

#### 5.2 Download the AI Model

1. In LM Studio, click the **"Search"** tab (left sidebar)
2. In the search box, type: `Qwen/Qwen2.5-7B-Instruct`
3. Find the model in the results (usually from "Qwen" or "QwenLM")
4. Click the **"Download"** button
5. Wait for download to complete (~4-5GB, takes 10-20 minutes depending on internet speed)

**Why this model?** Qwen 2.5 7B Instruct provides excellent performance for forensic analysis tasks with better reasoning capabilities than the 3B model. Requires 4GB+ VRAM for optimal performance.

#### 5.3 Load the Model in LM Studio

1. Click the **"Chat"** tab (left sidebar)
2. Click the model dropdown at the top
3. Select `Qwen/Qwen2.5-3B-Instruct` (the one you just downloaded)
4. Wait for it to load (may take 30-60 seconds)

#### 5.4 Start the LM Studio Server

1. Click the **"Local Server"** tab (left sidebar)
2. Click the **"Start Server"** button
3. You should see: "Server running on http://localhost:1234"
4. **Keep LM Studio running** - don't close it while using EVI-SCAN

**What just happened?** You started a local AI server that EVI-SCAN can talk to!

---

### Step 6: Start EVI-SCAN

**Option A: Quick Start (Easiest)**

**Windows:**
```bash
scripts\QUICK_START.bat
```
Just double-click `QUICK_START.bat` in File Explorer!

**Mac/Linux:**
```bash
chmod +x scripts/QUICK_START.sh
./scripts/QUICK_START.sh
```

**Option B: Manual Start**

**Windows:**
```bash
python scripts/start_enhanced_web_interface.py
```

**Mac/Linux:**
```bash
python3 scripts/start_enhanced_web_interface.py
```

**Expected Output:**
```
 * Running on http://127.0.0.1:5000
 * Running on http://localhost:5000
Press CTRL+C to quit
```

**What just happened?** You started the web server! Keep this window open.

---

### Step 7: Open EVI-SCAN in Your Browser

1. **Open your web browser** (Chrome, Firefox, Edge, Safari - any browser works)

2. **Type this address in the address bar:**
   ```
   http://localhost:5000
   ```
   Or: `http://127.0.0.1:5000`

3. **Press Enter**

4. **You should see:**
   - **Development Mode**: Case Manager page (if `DEV_MODE=True`)
   - **Production Mode**: Login/Signup page

5. **If you see the login page:**
   - Click "Sign Up" to create an account
   - Fill in your email and password
   - Click "Sign Up"
   - Then login with your credentials

**Congratulations! 🎉 EVI-SCAN is now running!**

---

### Step 8: Test It Out

1. **Upload a test file:**
   - Click "Upload UFDR File" or "New Case"
   - Select a ZIP file from `FORENSIC/data/UFDR's(new)/` (if available)
   - Or upload your own UFDR ZIP file

2. **Try a query:**
   - Type in the search box: `"show messages with external partners"`
   - Press Enter
   - You should see results!

3. **If everything works:** You're all set! 🎊

---

## 🔧 Troubleshooting for Beginners

### Problem: "Python is not recognized" or "python: command not found"

**Solution:**
- Python is not installed or not in your PATH
- **Windows:** Reinstall Python and make sure to check "Add Python to PATH"
- **Mac/Linux:** Use `python3` instead of `python`

### Problem: "git: command not found"

**Solution:**
- Git is not installed
- Install Git from https://git-scm.com/downloads
- Restart your terminal/command prompt after installing

### Problem: "Module not found" or "No module named 'flask'"

**Solution:**
- Python packages didn't install correctly
- Run the setup script again:
  ```bash
  cd FORENSIC
  python scripts/setup_with_lm_studio.py
  ```

### Problem: "Port 5000 already in use"

**Solution:**
- Another program is using port 5000
- Close other applications
- Or wait a few minutes and try again

### Problem: "LM Studio connection failed"

**Solution:**
1. Make sure LM Studio is installed and running
2. Make sure the model `Qwen/Qwen2.5-7B-Instruct` is downloaded
3. Make sure the LM Studio server is started (Local Server tab)
4. Check that it says "Server running on http://localhost:1234"
5. Restart both LM Studio and EVI-SCAN

### Problem: "Permission denied" (Mac/Linux)

**Solution:**
- Use `python3` instead of `python`
- Or add `sudo` before commands (but be careful!)

### Problem: "Can't find the scripts folder"

**Solution:**
- Make sure you're in the `FORENSIC` folder
- Check: `cd EVI-SCAN/FORENSIC`
- Then list files: `dir` (Windows) or `ls` (Mac/Linux)
- You should see a `scripts` folder

---

## 🎯 Minimal Setup (Without AI Chat)

If you don't need the AI Chat Assistant feature, you can skip LM Studio:

```bash
# Navigate to FORENSIC directory
cd EVI-SCAN/FORENSIC

# Run minimal setup (Windows)
python scripts/setup_minimal.py

# OR (Mac/Linux)
python3 scripts/setup_minimal.py

# Start the application
python scripts/start_enhanced_web_interface.py
# OR
python3 scripts/start_enhanced_web_interface.py
```

**What works without LM Studio:**
- ✅ File upload and analysis
- ✅ Natural language queries
- ✅ Scenario detection
- ✅ All core features

**What doesn't work without LM Studio:**
- ❌ AI Chat Assistant
- ❌ Conversational AI features

---

## 🚀 Usage

### Example Queries

- `"show messages with external partners"`
- `"find processing fee requests"`
- `"show OTP messages"`
- `"find suspicious activities"`
- `"show communications with Ravi Kumar"`

### Supported Scenarios

The system includes three **built-in scenario detectors** as examples:

1. **Insider Data Leak**: Unauthorized data sharing with external partners  
2. **Scam Network**: Job scam operations with victim targeting  
3. **SIM Swap Attack**: OTP-based attacks and telecom fraud  

These are **reference scenarios only**. Because the engine works on a normalized UFDR schema (contacts, calls, messages, metadata, media), EVI-SCAN can be applied to **any case type** (e.g., homicide, extortion, harassment) as long as the UFDR export follows the expected structure.

### Upload UFDR Files

1. Click "Upload UFDR File" in the web interface
2. Select or drag-and-drop a UFDR JSON or ZIP file
3. System automatically extracts ZIP files and normalizes the data into the UFDR schema
4. Built-in scenario detectors run (if applicable)
5. Start querying with natural language

### Supported File Formats & Structure

- **ZIP Files**: UFDR ZIP archives (standard format) typically containing:
  - `Artifacts/` folder with JSON files (Calls, Contacts, SMS, WhatsApp)
  - `__metadata__/` folder with case and device information
  - `Media/Images/` and `Media/Videos/` folders (optional evidence media)
  - `Reports/summary.json` (optional summary report)

As long as your export follows this general layout (or can be transformed into it), EVI-SCAN can be used on **any kind of case**, not just the three example scenarios.

---

## 📁 Project Structure

```
EVI-SCAN/
├── FORENSIC/                    # Main forensic analysis application
│   ├── web_interface.py        # Flask web server (main entry point)
│   ├── session_db.py          # Session and case management database
│   ├── security_enhancements.py # Security features
│   ├── core/                   # Core forensic engine modules
│   ├── engines/                # Query engine modules
│   ├── utils/                  # Utility modules
│   ├── templates/              # Web UI templates
│   ├── static/                 # Static web assets
│   ├── data/                   # Data directories
│   ├── scripts/                # Setup and startup scripts
│   └── tests/                  # Test files
├── Image Model/                # Image analysis system
│   └── EBI-scan-main/          # Face & object detection system
│       ├── backend/            # FastAPI backend
│       └── frontend/           # React frontend
├── Authentication/             # Authentication system
├── database/                   # Database management
├── chat improvements/          # Enhanced chat features
├── docs/                       # Documentation
├── README.md                  # This file
├── PROJECT_ANALYSIS.md        # Comprehensive project analysis
└── .gitignore                 # Git ignore rules
```

> **📖 For detailed project structure, see [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md)**

---

## 🛠️ Technology Stack

### Backend
- **Python 3.7+**
- **Flask 2.3.3** - Web framework (Forensic Analysis)
- **FastAPI 0.104.1** - Web framework (Image Model)
- **Pandas 2.1.3** - Data processing
- **RapidFuzz 3.9.7** - Fuzzy string matching
- **ORJSON** - Fast JSON processing
- **SQLite3** - Session and case management database
- **PostgreSQL** - Image Model database (optional)
- **SQLAlchemy 2.0.23** - ORM for Image Model
- **bcrypt** - Password hashing for authentication
- **ReportLab 4.0.7** - PDF report generation

### AI/ML (Optional)
- **LM Studio** - Local LLM server (for text chat)
- **Transformers 4.35.2** - Hugging Face models (compatible with PyTorch 2.1+)
- **PyTorch 2.1+** - Deep learning framework (optional)
- **Accelerate** - Model optimization (optional)
- **DeepFace** - Face recognition and detection
- **YOLOv8** - Object detection (Ultralytics)
- **OpenCV** - Image processing

### Frontend
- **HTML5/CSS3**
- **Bootstrap 5.3.0**
- **JavaScript** (Vanilla)
- **Font Awesome 6.4.0**

> **📖 For detailed technology stack information, see [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md)**

---

## 📚 Documentation

- **[PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md)** - 📋 **Comprehensive project analysis** (architecture, components, data flow, technical details)
- **[INSTALLATION.md](INSTALLATION.md)** - 📦 Complete installation guide
- **[docs/setup/START_HERE.txt](docs/setup/START_HERE.txt)** - Quick start instructions
- **[docs/setup/SETUP_SUMMARY.md](docs/setup/SETUP_SUMMARY.md)** - Quick setup reference
- **[docs/guides/FULL_FUNCTIONALITY_GUIDE.md](docs/guides/FULL_FUNCTIONALITY_GUIDE.md)** - Complete feature guide
- **[FORENSIC/PROJECT_STRUCTURE.md](FORENSIC/PROJECT_STRUCTURE.md)** - Project structure and organization
- **[FOLDER_STRUCTURE.md](FOLDER_STRUCTURE.md)** - Visual folder structure guide
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes

---

## 🧪 Testing

Test data is included in `FORENSIC/data/UFDR's(new)/`:
- `case 1 Kidnapping Conspiracy.zip`
- `case 2 Human Trafficking.zip`
- `case 3 Cyber Fraud  Phishing.zip`
- `case 4 Illegal Surveillance.zip`
- `case 5 Domestic Violence Evidence.zip`
- `case 6 Smuggling Operations.zip`
- `HOMICIDE_UFDR.zip`
- `UFDR_FILE.format.zip`

Upload these ZIP files to test the system!

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📝 License

This project is part of the SIH (Smart India Hackathon) Official submission.

---

## 🙏 Acknowledgments

- Built for Smart India Hackathon (SIH)
- Uses LM Studio for local LLM inference
- Powered by Flask and modern web technologies

---

## 📞 Support

If you encounter any issues:
1. Check the [Installation Guide](#-complete-installation-guide-step-by-step) above
2. Review [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md) for technical details
3. Check [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions
4. Open an issue on [GitHub](https://github.com/debu-devesh/EVI-SCAN/issues)

---

## ⭐ Show Your Support

If you find this project useful, please give it a ⭐ on GitHub!

---

<div align="center">

**Made with ❤️ for Digital Forensics**

[Report Bug](https://github.com/debu-devesh/EVI-SCAN/issues) • [Request Feature](https://github.com/debu-devesh/EVI-SCAN/issues) • [Documentation](PROJECT_ANALYSIS.md)

</div>
