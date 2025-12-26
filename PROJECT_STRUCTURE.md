# Project Structure Guide

This document explains the organized folder structure of the EVI SCAN project.

## 📁 Directory Structure

```
FORENSIC/
├── web_interface.py          # Main Flask web application (entry point)
├── session_db.py           # Session and case management database module
├── security_enhancements.py # Security features and enhancements
├── sessions.db              # SQLite database for sessions/cases (auto-created)
│
├── core/                     # Core forensic engine modules
│   ├── __init__.py
│   ├── ufdr_processor.py
│   ├── ufdr_file_handler.py
│   ├── ufdr_forensic_command_engine.py
│   └── enhanced_data_extractor.py
│
├── engines/                  # Query and analysis engines
│   ├── __init__.py
│   ├── nl_query_engine.py
│   ├── enhanced_nl_query_engine.py
│   ├── simplified_nl_query_engine.py
│   ├── ai_ufdr_retrieval_engine.py
│   ├── rag_engine.py
│   └── smart_analyzer.py
│
├── utils/                    # Utility modules
│   ├── confidence.py
│   ├── ufdr_parser.py
│   └── image_citation.py
│
├── templates/                # HTML templates for web UI
│   ├── index.html
│   ├── enhanced_index.html
│   ├── ai_index.html
│   └── case_manager/        # Case management UI templates
│       ├── case_manager.html
│       └── *.md            # Case manager documentation
│
├── static/                   # Static web assets
│   └── chimes/              # Audio files
│
├── data/                     # Data directories
│   ├── UFDR's(new)/         # Test ZIP UFDR files
│   ├── uploads/             # Temporary upload directory
│   └── uploaded_ufdrs/      # Processed user uploads
│
├── scripts/                  # Setup and startup scripts
│   ├── setup_minimal.py
│   ├── setup_with_lm_studio.py
│   ├── start_enhanced_web_interface.py
│   ├── start_lm_studio_server.py
│   ├── start_lm_studio_server.bat
│   ├── start_web.bat
│   ├── QUICK_START.bat
│   ├── QUICK_START.sh
│   └── test_comprehensive_web.bat
│
├── tests/                    # Test files
│   ├── test_keyword_recognition.py
│   └── simple_example_queries.py
│
├── requirements.txt          # Full dependencies
└── requirements_minimal.txt  # Minimal dependencies
```

## 🔧 Import Paths

### From web_interface.py:
```python
from engines.nl_query_engine import NaturalLanguageUFDR
from engines.enhanced_nl_query_engine import EnhancedNaturalLanguageUFDR
from engines.ai_ufdr_retrieval_engine import AIUFDRRetrievalEngine
from engines.rag_engine import UFDRRAGEngine
from engines.smart_analyzer import smart_analyzer
from core.enhanced_data_extractor import enhanced_extractor
from utils.confidence import confidence_calculator
from utils.ufdr_parser import ufdr_parser
from utils.image_citation import image_citation_extractor
from session_db import (
    init_session_db, create_session, update_session_access, get_session,
    save_chat_message, get_chat_history, clear_chat_history,
    save_preference, get_preferences,
    save_query, get_query_history,
    get_sessions_by_case, get_all_sessions,
    create_case, get_case, get_all_cases, update_case, delete_case
)
```

### From test files:
```python
# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

```

## 📂 Data Paths

- **Test data**: `data/UFDR's(new)/` (ZIP UFDR files)
- **User uploads**: `data/uploaded_ufdrs/`
- **Temporary uploads**: `data/uploads/`

## 🚀 Running the Application

### Windows:
```batch
cd FORENSIC
scripts\QUICK_START.bat
# OR
scripts\start_web.bat
```

### Mac/Linux:
```bash
cd FORENSIC
bash scripts/QUICK_START.sh
# OR
python scripts/start_enhanced_web_interface.py
```

## 📝 Notes

- All scripts in `scripts/` automatically change to the FORENSIC directory
- Test files use relative paths: `../data/UFDR's(new)/` for ZIP UFDR files
- The web interface uses `data/uploaded_ufdrs` for user uploads
- All imports are relative to the FORENSIC directory

