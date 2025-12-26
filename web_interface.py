#!/usr/bin/env python3
"""
EVI SCAN - UFDR Forensic Analysis Web Interface

A comprehensive web-based forensic analysis system for analyzing UFDR 
(Unified Forensic Data Records) files with natural language querying, 
scenario detection, and AI-powered insights.

Features:
- Natural Language Query Processing
- AI-Powered Chat Assistant (LM Studio integration)
- Real-time Forensic Analysis
- ZIP UFDR File Support
- Case Management
- Session Persistence
"""

# Standard library imports
import json
import os
import re
import secrets
import shutil
import sqlite3
import logging
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path
from io import BytesIO

# Third-party imports
import bcrypt
import requests
from flask import (
    Flask, render_template, request, jsonify, session, Response,
    stream_with_context, send_file, redirect, url_for, flash
)
from werkzeug.utils import secure_filename
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    # Note: Logger not yet defined, using print instead
    print("Warning: ReportLab not available. PDF export will be disabled. Install with: pip install reportlab")

from engines.nl_query_engine import NaturalLanguageUFDR
from engines.enhanced_nl_query_engine import EnhancedNaturalLanguageUFDR
from engines.ai_ufdr_retrieval_engine import AIUFDRRetrievalEngine
# RAG engine disabled - using keyword-based extraction instead
# from engines.rag_engine import UFDRRAGEngine
from engines.smart_analyzer import smart_analyzer
from utils.confidence import confidence_calculator
from utils.ufdr_parser import ufdr_parser
from utils.image_citation import image_citation_extractor
from core.enhanced_data_extractor import enhanced_extractor
from core.hybrid_zip_parser import HybridZipParser
from core.semantic_data_extractor import semantic_extractor
from core.key_characters_analyzer import key_characters_analyzer

# Configure logging (must be before logger is used)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security enhancements
try:
    from security.security_enhancements import (
        encryption, audit_logger, RBAC,
        audit_action, encrypt_sensitive_field, decrypt_sensitive_field
    )
    from security import create_audit_table, sanitize_input
    # require_permission is a method of RBAC class
    require_permission = RBAC.require_permission
    # Stub functions for compatibility (if used elsewhere)
    require_case_access = lambda f: f
    configure_secure_sessions = lambda app: None
    calculate_file_hash = lambda filepath: None
    SECURITY_AVAILABLE = True
    logger.info("Security enhancements module loaded")
except ImportError as e:
    SECURITY_AVAILABLE = False
    logger.warning(f"Security enhancements not available: {e}")
except Exception as e:
    SECURITY_AVAILABLE = False
    logger.warning(f"Security enhancements not available: {e}")

# Session persistence
def persist_chat_message(session_id, role, content, metadata=None):
    """Helper to save chat message to both in-memory and database"""
    # In-memory (for backward compatibility)
    if session_id not in CHAT_HISTORIES:
        CHAT_HISTORIES[session_id] = []
    CHAT_HISTORIES[session_id].append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})
    
    # Database persistence
    if SESSION_DB_AVAILABLE:
        try:
            save_chat_message(session_id, role, content, metadata=metadata)
        except Exception as e:
            logger.warning(f"Failed to persist chat message to database: {e}")

# Session persistence
try:
    import sys
    import os
    # Add database/code to path for session_db import
    _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
    if _database_code_path not in sys.path:
        sys.path.insert(0, _database_code_path)
    from session_db import (
        init_session_db, create_session, update_session_access, get_session,
        save_chat_message, get_chat_history, get_chat_history_from_related_sessions, clear_chat_history,
        save_preference, get_preferences,
        save_query, get_query_history,
        get_sessions_by_case, get_all_sessions,
        create_case, get_case, get_all_cases, update_case, delete_case,
        save_session_file, get_session_files, delete_session_file, clear_session_files
    )
    SESSION_DB_AVAILABLE = True
    logger.info("Session database module loaded")
    # Initialize database on import
    success, error_msg = init_session_db()
    if success:
        logger.info("Session database initialized successfully")
        # Initialize audit table if security is available
        if SECURITY_AVAILABLE and SESSION_DB_AVAILABLE:
            try:
                create_audit_table()
                logger.info("Audit table initialized")
            except Exception as e:
                logger.warning(f"Could not initialize audit table: {e}")
    else:
        error_message = error_msg or "Unknown error during initialization"
        logger.error(f"Failed to initialize session database: {error_message}")
        SESSION_DB_AVAILABLE = False
except ImportError as e:
    SESSION_DB_AVAILABLE = False
    logger.warning(f"Session database not available: {e}")

app = Flask(__name__)
# Set secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32) if 'secrets' in dir() else 'evi-scan-forensic-tool-secret-key-change-in-production')

# Configure session settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Only use Secure cookies in production (HTTPS)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cookies on any domain/IP
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Configure secure sessions if security is available (but override Secure flag for HTTP)
if SECURITY_AVAILABLE:
    try:
        # Temporarily disable secure flag for HTTP access
        original_secure = app.config.get('SESSION_COOKIE_SECURE', False)
        configure_secure_sessions(app)
        # Override secure flag if not using HTTPS
        app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP access
        app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cookies on any domain/IP
        logger.info("Secure session configuration applied (HTTP mode)")
    except Exception as e:
        logger.warning(f"Could not apply secure session config: {e}")

# Configure Flask to ignore upload directory in reloader (prevents restarts during file uploads)
# This is a workaround for Flask's auto-reloader being too sensitive to file changes
if app.debug:
    import sys
    # Add upload directory to ignored patterns if using watchdog
    try:
        from werkzeug.serving import is_running_from_reloader
        # This helps prevent reloader from triggering on upload directory changes
        pass
    except:
        pass

# Development Mode - Set to True to bypass authentication
# Set environment variable: export DEV_MODE=True to enable (or set DEV_MODE=True in code)
DEV_MODE = False  # ENABLED - Set to False for production
# For development, set DEV_MODE = True or export DEV_MODE=True
# For production, set DEV_MODE = False or export DEV_MODE=False

if DEV_MODE:
    logger.warning("⚠️  DEVELOPMENT MODE ENABLED - Authentication is DISABLED")
    logger.warning("⚠️  You can access EVI-SCAN directly without login")
    logger.warning("⚠️  Set DEV_MODE=False for production!")
else:
    logger.info("🔒 PRODUCTION MODE - Authentication is REQUIRED")

# Configure template paths to include Authentication templates and Security templates
from jinja2 import FileSystemLoader, ChoiceLoader
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVI_SCAN_DIR = os.path.dirname(BASE_DIR)
AUTH_TEMPLATES = os.path.join(EVI_SCAN_DIR, 'Authentication', 'templates')
FORENSIC_TEMPLATES = os.path.join(BASE_DIR, 'templates')
SECURITY_TEMPLATES = os.path.join(BASE_DIR, 'security', 'templates')
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(FORENSIC_TEMPLATES),
    FileSystemLoader(AUTH_TEMPLATES),
    FileSystemLoader(SECURITY_TEMPLATES)
])

# Authentication Database Configuration
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')
captcha_storage = {}

# Configuration
UPLOAD_FOLDER = 'data/uploaded_ufdrs'
ALLOWED_EXTENSIONS = {'json', 'zip'}

# Configure Flask for large file uploads (after UPLOAD_FOLDER is defined)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB max file size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Chat history storage (in-memory, per session)
# Format: {session_id: [{"role": "user|assistant", "content": "...", "timestamp": "..."}, ...]}
CHAT_HISTORIES = {}

# Create upload directory
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize NL query engines (answers will be restricted to ACTIVE_DATA)
nl_engine = NaturalLanguageUFDR({})
enhanced_nl_engine = EnhancedNaturalLanguageUFDR({})

# Initialize the AI-powered retrieval engine
ai_retrieval_engine = AIUFDRRetrievalEngine({})

# Initialize simplified engine for comprehensive analysis
from engines.simplified_nl_query_engine import SimplifiedNLQueryEngine
simplified_engine = SimplifiedNLQueryEngine()
# RAG engine disabled - using keyword-based extraction instead
rag_engine = None  # UFDRRAGEngine()

# Initialize semantic extractor without RAG engine (will use keyword-based extraction)
from core.semantic_data_extractor import SemanticDataExtractor
semantic_extractor = SemanticDataExtractor(rag_engine=None)
# LLM Configuration
USE_LLM = True  # Enable LM Studio integration (Required for AI Chat Assistant)
LLM_MODEL = "Qwen/Qwen2.5-7B-Instruct"  # LM Studio model (Qwen 2.5 7B Instruct - optimized for better performance)
LLM_URL = "http://localhost:1234/v1/chat/completions"  # LM Studio API endpoint

# LLM Context Length Configuration
# Set this to match your model's context length in LM Studio
# Common values: 2048 (small models), 4096 (medium), 8192 (large), 32768 (very large)
LLM_CONTEXT_LENGTH = int(os.environ.get('LLM_CONTEXT_LENGTH', '2048'))  # Default: 2048, can be overridden via environment variable

# Qwen2.5-VL-7B Configuration
USE_QWEN_VL = False  # DISABLED - Enable Qwen2.5-VL-7B for multimodal (images/videos) - Set to True to enable
QWEN_VL_MODEL_NAME = "Qwen/Qwen2.5-VL-7B-Instruct"
QWEN_VL_MODEL = None
QWEN_VL_PROCESSOR = None
QWEN_VL_LOADED = False

# Log LLM configuration at startup
if USE_LLM:
    logger.info(f"LLM integration enabled - Model: {LLM_MODEL}, URL: {LLM_URL}, Context Length: {LLM_CONTEXT_LENGTH} tokens")
else:
    logger.warning("LLM integration disabled - AI Chat Assistant will not be available")

if USE_QWEN_VL:
    logger.info(f"Qwen2.5-VL-7B multimodal support enabled - Model: {QWEN_VL_MODEL_NAME}")
else:
    logger.info("Qwen2.5-VL-7B multimodal support disabled")

# Available LLM models
AVAILABLE_MODELS = ["qwen2.5", "llama3.2", "mistral"]

# Active uploaded UFDR context
ACTIVE_FILENAME = None
ACTIVE_DATA = {}

def get_current_data():
    """Return only actively uploaded UFDR data. No synthetic fallback."""
    try:
        if ACTIVE_DATA:
            return ACTIVE_DATA
    except Exception:
        pass
    return {}

def rebuild_rag_index():
    """Rebuild the RAG index with current data."""
    # RAG is disabled - return early
    if rag_engine is None:
        logger.debug("RAG engine is disabled - skipping index rebuild")
        return False
    
    data_src = get_current_data()
    try:
        # Clear old RAG index first
        rag_engine.chunks = []
        rag_engine.index = None
        rag_engine._embed_cache.clear()
        rag_engine._query_cache.clear()
        
        # Check if RAG engine is available before building
        if not rag_engine.available:
            logger.warning("⚠️ RAG engine dependencies missing - cannot build index")
            logger.warning("⚠️ Install with: pip install numpy faiss-cpu sentence-transformers")
            return False
        
        # Build new index with current data
        success = rag_engine.build_index(data_src)
        
        if success:
            # Update semantic extractor with rebuilt RAG engine
            global semantic_extractor
            if semantic_extractor:
                semantic_extractor.rag_engine = rag_engine
                semantic_extractor._data_index = {}  # Reset data index to force rebuild
                logger.info("✅ Semantic extractor data index reset")
            
            logger.info("✅ RAG index rebuilt with fresh data, semantic extractor updated")
            return True
        else:
            logger.warning("⚠️ RAG index build failed - check logs above for details")
            return False
    except Exception as e:
        logger.error(f"❌ Failed to rebuild RAG index: {e}", exc_info=True)
        return False


def is_query_too_broad(query: str) -> bool:
    """
    Heuristic to detect overly broad queries that are likely to produce
    generic, non-data-grounded answers.
    """
    if not query or not isinstance(query, str):
        return False

    q = query.strip().lower()

    # Very short generic prompts
    if len(q) < 12:
        return True

    generic_phrases = [
        "what can you tell me about the ufdr",
        "what can you tell me about this ufdr",
        "what can you tell me about this file",
        "tell me about the ufdr",
        "tell me about this ufdr",
        "tell me about this case",
        "summarize this file",
        "give me a summary",
        "overall summary",
        "overall analysis",
        "analyse this ufdr",
        "analyze this ufdr",
        "analyze this file",
        "general overview",
    ]

    for phrase in generic_phrases:
        if phrase in q:
            return True

    # If user only says "tell me about this" or similar without any domain terms
    if ("tell me" in q or "what can you tell" in q) and not any(
        kw in q
        for kw in ["message", "messages", "sms", "whatsapp", "call", "calls",
                   "contact", "contacts", "timeline", "date", "time",
                   "money", "transaction", "otp", "location"]
    ):
        return True

    return False


def generate_forensic_overview(data_src: dict) -> dict:
    """
    Generate a pre-summarized forensic overview object instead of dumping raw data.
    This prevents hallucination for summary questions.
    """
    overview = {
        "contacts_count": 0,
        "messages_count": 0,
        "calls_count": 0,
        "locations_count": 0,
        "date_range": None,
        "top_apps": [],
        "most_active_contacts": [],
        "activity_spikes": [],
        "deleted_artifacts": False
    }
    
    all_dates = []
    contact_frequency = {}
    app_types = set()
    
    for filename, data in data_src.items():
        if filename.startswith('_'):
            continue
            
        if isinstance(data, dict):
            # Handle devices array format
            if 'devices' in data:
                devices = data['devices']
                for device in devices:
                    if isinstance(device, dict):
                        overview["contacts_count"] += len(device.get('contacts', []))
                        overview["messages_count"] += len(device.get('messages', []))
                        overview["calls_count"] += len(device.get('call_logs', []))
                        overview["locations_count"] += len(device.get('locations', []))
                        
                        # Extract dates from messages
                        for msg in device.get('messages', []):
                            if msg.get('timestamp'):
                                all_dates.append(msg.get('timestamp'))
                            if msg.get('source'):
                                app_types.add(msg.get('source'))
                        
                        # Count contact activity
                        for msg in device.get('messages', []):
                            contact = msg.get('from') or msg.get('sender')
                            if contact:
                                contact_frequency[contact] = contact_frequency.get(contact, 0) + 1
            else:
                # Flat structure
                overview["contacts_count"] += len(data.get('contacts', []))
                overview["messages_count"] += len(data.get('messages', []))
                overview["calls_count"] += len(data.get('call_logs', []))
                overview["locations_count"] += len(data.get('locations', []))
                
                # Extract dates
                for msg in data.get('messages', []):
                    if msg.get('timestamp'):
                        all_dates.append(msg.get('timestamp'))
                    if msg.get('source'):
                        app_types.add(msg.get('source'))
                
                # Count contact activity
                for msg in data.get('messages', []):
                    contact = msg.get('from') or msg.get('sender')
                    if contact:
                        contact_frequency[contact] = contact_frequency.get(contact, 0) + 1
    
    # Calculate date range
    if all_dates:
        try:
            from datetime import datetime
            valid_dates = [d for d in all_dates if d and isinstance(d, str)]
            if valid_dates:
                # Try to parse dates
                parsed_dates = []
                for d in valid_dates[:100]:  # Sample first 100
                    try:
                        # Try common formats
                        for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
                            try:
                                parsed_dates.append(datetime.strptime(d[:19], fmt))
                                break
                            except:
                                continue
                    except:
                        continue
                
                if parsed_dates:
                    min_date = min(parsed_dates)
                    max_date = max(parsed_dates)
                    overview["date_range"] = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
        except Exception as e:
            logger.debug(f"Error calculating date range: {e}")
    
    # Top apps
    overview["top_apps"] = list(app_types)[:5]
    
    # Most active contacts (top 5)
    if contact_frequency:
        sorted_contacts = sorted(contact_frequency.items(), key=lambda x: x[1], reverse=True)
        overview["most_active_contacts"] = [name for name, count in sorted_contacts[:5]]
    
    return overview


def rewrite_vague_query(query: str) -> str:
    """
    Auto-rewrite vague questions to specific forensic queries.
    Prevents hallucination by making intent explicit.
    """
    query_lower = query.lower().strip()
    
    vague_patterns = {
        "what can you tell me about this ufdr file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "what can you tell me about this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "what can you tell me about this file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "tell me about this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "tell me about this case": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "analyze this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "analyze this file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
    }
    
    for pattern, rewrite in vague_patterns.items():
        if pattern in query_lower:
            logger.info(f"🔄 Rewriting vague query: '{query}' → '{rewrite}'")
            return rewrite
    
    return query  # Return original if not vague


def get_query_refinement_suggestions(query: str, data_src: dict) -> dict:
    """
    Build user-friendly suggestions to refine an overly broad query,
    optionally using basic stats from ACTIVE_DATA.
    """
    # Basic stats from ACTIVE_DATA if available
    stats = {
        "contacts": 0,
        "messages": 0,
        "calls": 0,
    }

    try:
        if data_src:
            for _, file_data in data_src.items():
                if not isinstance(file_data, dict):
                    continue
                contacts = file_data.get("contacts", [])
                messages = file_data.get("messages", [])
                calls = file_data.get("calls", [])
                if isinstance(contacts, list):
                    stats["contacts"] += len(contacts)
                if isinstance(messages, list):
                    stats["messages"] += len(messages)
                if isinstance(calls, list):
                    stats["calls"] += len(calls)
    except Exception:
        pass

    suggestions = [
        "Show all messages and calls for this UFDR.",
        "Summarize the communication timeline for this device.",
        "List the top contacts by number of messages and calls.",
        "Find messages that mention money, payments, or transactions.",
        "Show suspicious or high-risk conversations in this UFDR.",
    ]

    # Tailor suggestions slightly based on available data
    tailored = []
    if stats["messages"] > 0:
        tailored.append(
            f"Summarize key patterns from the {stats['messages']} messages in this UFDR."
        )
        tailored.append(
            "Find messages that look related to threats, blackmail, or fraud."
        )
    if stats["calls"] > 0:
        tailored.append(
            f"Analyze the {stats['calls']} calls and highlight unusual calling patterns."
        )
    if stats["contacts"] > 0:
        tailored.append(
            f"Show relationships between the {stats['contacts']} contacts and the main suspect."
        )

    if tailored:
        suggestions = tailored + suggestions

    return {
        "status": "BROAD_QUERY",
        "message": "Your question is very broad, so the AI may answer generically without using the uploaded UFDR data effectively.",
        "original_query": query,
        "stats": stats,
        "suggested_queries": suggestions[:8],  # keep list short
    }

def init_qwen_vl_model():
    """Initialize Qwen2.5-VL-7B model for multimodal processing."""
    global QWEN_VL_MODEL, QWEN_VL_PROCESSOR, QWEN_VL_LOADED
    
    if QWEN_VL_LOADED:
        return QWEN_VL_MODEL, QWEN_VL_PROCESSOR
    
    if not USE_QWEN_VL:
        return None, None
    
    try:
        logger.info("Loading Qwen2.5-VL-7B model...")
        from transformers import AutoProcessor, Qwen2VLForConditionalGeneration
        import torch
        
        # Check if CUDA is available
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Loading model on device: {device}")
        
        # Load model with proper configuration
        # Use trust_remote_code=True for Qwen models and force download if cache is corrupted
        try:
            # First try loading without quantization (more reliable)
            logger.info("Loading Qwen2.5-VL-7B model (full precision)...")
            QWEN_VL_MODEL = Qwen2VLForConditionalGeneration.from_pretrained(
                QWEN_VL_MODEL_NAME,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            # Move to device manually
            QWEN_VL_MODEL = QWEN_VL_MODEL.to(device)
            logger.info(f"Model loaded successfully on {device}")
        except Exception as e:
            # If there's a size mismatch, the cache might be corrupted
            if "size mismatch" in str(e).lower() or "shape" in str(e).lower():
                logger.warning("Model cache appears corrupted. Attempting to force re-download...")
                try:
                    # Force re-download by clearing cache and downloading fresh
                    logger.info("Clearing corrupted cache and re-downloading model...")
                    QWEN_VL_MODEL = Qwen2VLForConditionalGeneration.from_pretrained(
                        QWEN_VL_MODEL_NAME,
                        torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                        trust_remote_code=True,
                        low_cpu_mem_usage=True,
                        force_download=True,  # Force re-download
                        resume_download=False  # Don't resume, start fresh
                    )
                    QWEN_VL_MODEL = QWEN_VL_MODEL.to(device)
                    logger.info(f"Model re-downloaded and loaded on {device}")
                except Exception as e2:
                    logger.error(f"Failed to re-download model: {e2}")
                    logger.error("You may need to manually clear the cache at: ~/.cache/huggingface/hub/")
                    raise e  # Re-raise original error
            else:
                # Other error, re-raise
                raise
        
        QWEN_VL_PROCESSOR = AutoProcessor.from_pretrained(QWEN_VL_MODEL_NAME)
        QWEN_VL_LOADED = True
        logger.info("✅ Qwen2.5-VL-7B model loaded successfully")
        return QWEN_VL_MODEL, QWEN_VL_PROCESSOR
    except ImportError as e:
        logger.error(f"Failed to import transformers for Qwen2.5-VL: {e}")
        logger.error("Install with: pip install transformers torch pillow")
        return None, None
    except Exception as e:
        logger.error(f"Failed to load Qwen2.5-VL-7B model: {e}")
        logger.error("Model may not be downloaded. Download from Hugging Face first.")
        return None, None

def extract_zip_with_hybrid_parser(zip_path, extract_to=None):
    """
    Extract ZIP file using hybrid parser (heuristics + LLM fallback).
    Falls back to standard parser if hybrid parser fails.
    
    Args:
        zip_path: Path to ZIP file
        extract_to: Optional extraction directory
        
    Returns:
        Extracted data structure in UFDR format
    """
    import tempfile
    try:
        logger.info(f"🔍 Attempting hybrid ZIP parsing for: {zip_path}")
        
        # Initialize hybrid parser with LLM settings
        hybrid_parser = HybridZipParser(
            llm_url=LLM_URL if USE_LLM else None,
            llm_model=LLM_MODEL if USE_LLM else None
        )
        
        # Try hybrid parsing
        ufdr_data = hybrid_parser.parse_zip(zip_path)
        
        # Check if we got meaningful data
        if ufdr_data and (ufdr_data.get('contacts') or ufdr_data.get('messages') 
                          or ufdr_data.get('call_logs') or ufdr_data.get('locations')):
            logger.info("✅ Hybrid parser succeeded")
            
            # Extract images and videos - need to extract ZIP first to get full paths
            extracted_images = []
            extracted_videos = []
            
            # Extract ZIP to persistent location (not temp) so images persist across sessions
            if extract_to is None:
                # Try to get session_id from Flask session or request context
                try:
                    from flask import session, request
                    session_id = session.get('session_id') if session else None
                    # Also try request args
                    if not session_id:
                        session_id = request.args.get('session_id') if request else None
                except RuntimeError:
                    # Not in request context
                    session_id = None
                
                if session_id and session_id != 'None' and session_id != '':
                    # Use persistent location: data/extracted_ufdrs/session_id/
                    extract_base = os.path.join('data', 'extracted_ufdrs')
                    os.makedirs(extract_base, exist_ok=True)
                    extract_to = os.path.join(extract_base, session_id)
                    os.makedirs(extract_to, exist_ok=True)
                    logger.info(f"📂 Using persistent extraction path: {extract_to}")
                else:
                    # Fallback to temp if no session_id
                    extract_to = tempfile.mkdtemp()
                    logger.warning(f"⚠️ No session_id available, using temp directory: {extract_to} (images may not persist)")
            
            logger.info(f"Extracting ZIP to {extract_to} for image/video access")
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
                logger.info(f"ZIP extracted successfully to {extract_to}")
                
                # Get images and videos from ufdr_data (already detected by hybrid parser)
                images = ufdr_data.get('images', [])
                videos = ufdr_data.get('videos', [])
                
                logger.info(f"Found {len(images)} image entries and {len(videos)} video entries in parsed data")
                
                # Process images - they have relative paths from ZIP
                for img_info in images:
                    if isinstance(img_info, dict):
                        rel_path = img_info.get('path', '')
                        if rel_path:
                            # Handle both Windows and Unix path separators
                            rel_path_normalized = rel_path.replace('\\', '/')
                            full_path = os.path.join(extract_to, rel_path_normalized)
                            # Also try with original path format
                            if not os.path.exists(full_path):
                                full_path = os.path.join(extract_to, rel_path)
                            
                            if os.path.exists(full_path):
                                extracted_images.append({
                                    'path': full_path,
                                    'rel_path': rel_path_normalized,
                                    'name': img_info.get('name', os.path.basename(rel_path))
                                })
                            else:
                                logger.warning(f"Image path not found: {full_path} (rel_path: {rel_path})")
                
                # Also scan Media folder directly for any missed images
                media_images_path = os.path.join(extract_to, 'Media', 'Images')
                if os.path.exists(media_images_path):
                    for root, dirs, files in os.walk(media_images_path):
                        for file in files:
                            if file.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                                full_path = os.path.join(root, file)
                                rel_path = os.path.relpath(full_path, extract_to).replace('\\', '/')
                                # Check if already added
                                if not any(img.get('rel_path') == rel_path for img in extracted_images):
                                    extracted_images.append({
                                        'path': full_path,
                                        'rel_path': rel_path,
                                        'name': file
                                    })
                
                # Process videos
                for vid_info in videos:
                    if isinstance(vid_info, dict):
                        rel_path = vid_info.get('path', '')
                        if rel_path:
                            rel_path_normalized = rel_path.replace('\\', '/')
                            full_path = os.path.join(extract_to, rel_path_normalized)
                            if not os.path.exists(full_path):
                                full_path = os.path.join(extract_to, rel_path)
                            
                            if os.path.exists(full_path):
                                extracted_videos.append({
                                    'path': full_path,
                                    'rel_path': rel_path_normalized,
                                    'name': vid_info.get('name', os.path.basename(rel_path))
                                })
                
                # Also scan Media/Video folder directly
                media_videos_path = os.path.join(extract_to, 'Media', 'Video')
                if os.path.exists(media_videos_path):
                    for root, dirs, files in os.walk(media_videos_path):
                        for file in files:
                            if file.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
                                full_path = os.path.join(root, file)
                                rel_path = os.path.relpath(full_path, extract_to).replace('\\', '/')
                                if not any(vid.get('rel_path') == rel_path for vid in extracted_videos):
                                    extracted_videos.append({
                                        'path': full_path,
                                        'rel_path': rel_path,
                                        'name': file
                                    })
            
            logger.info(f"Hybrid parser extracted {len(extracted_images)} images and {len(extracted_videos)} videos")
            
            # Mark as hybrid parsed and include normalized data
            return {
                'hybrid_parsed': True,
                'ufdr_data': ufdr_data,  # Already normalized
                'json_files': {zip_path: ufdr_data},
                'structure': {
                    'artifacts': {
                        'contacts': ufdr_data.get('contacts', []),
                        'sms': [m for m in ufdr_data.get('messages', []) if m.get('source') == 'SMS'],
                        'whatsapp': [m for m in ufdr_data.get('messages', []) if m.get('source') == 'WhatsApp'],
                        'calls': ufdr_data.get('call_logs', []),
                        'location': ufdr_data.get('locations', [])
                    },
                    'metadata': {
                        'device_info': ufdr_data.get('device', {}),
                        'case_info': ufdr_data.get('case_info', {})
                    }
                },
                'images': extracted_images,
                'videos': extracted_videos,
                'extract_path': extract_to or tempfile.mkdtemp()
            }
        else:
            logger.warning("⚠️ Hybrid parser returned empty data, falling back to standard parser")
            raise Exception("Hybrid parser returned empty data")
            
    except Exception as e:
        logger.warning(f"⚠️ Hybrid parser failed: {e}, falling back to standard parser")
        # Fallback to standard parser
        return extract_zip_file(zip_path, extract_to)

def extract_zip_file(zip_path, extract_to=None):
    """Extract ZIP file and return extracted data structure following UFDR format."""
    import zipfile
    import tempfile
    
    if extract_to is None:
        extract_to = tempfile.mkdtemp()
    
    extracted_files = {
        'json_files': {},
        'images': [],
        'videos': [],
        'other_files': [],
        'extract_path': extract_to,
        'structure': {
            'artifacts': {},
            'metadata': {},
            'media': {},
            'reports': {}
        }
    }
    
    try:
        logger.info(f"Opening ZIP file: {zip_path}")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Skip testzip() for large files - it can be very slow
            # Just try to extract and catch errors if ZIP is invalid
            logger.info(f"Extracting ZIP to: {extract_to}")
            # Extract all files
            zip_ref.extractall(extract_to)
            logger.info("ZIP extraction completed successfully")
            
            # Scan extracted files and organize by structure
            file_count = 0
            max_files = 50000  # Safety limit to prevent memory issues (increased for large extractions)
            for root, dirs, files in os.walk(extract_to):
                if file_count >= max_files:
                    logger.warning(f"Reached maximum file limit ({max_files}). Stopping scan.")
                    break
                for file in files:
                    file_count += 1
                    if file_count % 100 == 0:
                        logger.info(f"Processing file {file_count}...")
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_to)
                    # Normalize path separators (handle both Windows \ and Unix /)
                    rel_path_normalized = rel_path.replace('\\', '/')
                    
                    # Organize by UFDR structure
                    if rel_path_normalized.startswith('Artifacts/'):
                        # Artifacts folder (Calls, Contacts, SMS, WhatsApp)
                        if file.endswith('.json'):
                            try:
                                # Check file size before loading (skip if too large - >10MB)
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit per JSON file
                                    logger.warning(f"Skipping large JSON file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    # Store with full path as key (use normalized path)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    # Also store in structure
                                    if 'Calls' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['calls'] = data
                                    elif 'Contacts' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['contacts'] = data
                                    elif 'SMS' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['sms'] = data
                                    elif 'WhatsApp' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['whatsapp'] = data
                                    elif 'Location' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['location'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading JSON file {rel_path}: {e}")
                                raise  # Re-raise memory errors
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    elif rel_path_normalized.startswith('__metadata__/'):
                        # Metadata folder (case_info, device_info, log)
                        if file.endswith('.json'):
                            try:
                                # Check file size before loading
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large metadata file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    if 'case_info' in rel_path_normalized:
                                        extracted_files['structure']['metadata']['case_info'] = data
                                    elif 'device_info' in rel_path_normalized:
                                        extracted_files['structure']['metadata']['device_info'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in metadata file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading metadata file {rel_path}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    elif rel_path_normalized.startswith('Media/'):
                        # Media folder (Images, Videos)
                        if file.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                            extracted_files['images'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
                            if 'Images' in rel_path_normalized:
                                if 'images' not in extracted_files['structure']['media']:
                                    extracted_files['structure']['media']['images'] = []
                                extracted_files['structure']['media']['images'].append({
                                    'path': file_path,
                                    'rel_path': rel_path_normalized,
                                    'name': file
                                })
                        
                        elif file.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
                            extracted_files['videos'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
                            if 'Videos' in rel_path_normalized or 'Video' in rel_path_normalized:
                                if 'videos' not in extracted_files['structure']['media']:
                                    extracted_files['structure']['media']['videos'] = []
                                extracted_files['structure']['media']['videos'].append({
                                    'path': file_path,
                                    'rel_path': rel_path_normalized,
                                    'name': file
                                })
                    
                    elif rel_path_normalized.startswith('Reports/'):
                        # Reports folder
                        if file.endswith('.json'):
                            try:
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large report file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    if 'summary' in rel_path_normalized:
                                        extracted_files['structure']['reports']['summary'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in report file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading report file {rel_path}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    else:
                        # Other files
                        if file.endswith('.json'):
                            try:
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large JSON file {rel_path_normalized} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in file {rel_path_normalized}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading JSON file {rel_path_normalized}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path_normalized}: {e}")
                        else:
                            extracted_files['other_files'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
        
        logger.info(f"Extracted ZIP: {len(extracted_files['json_files'])} JSON, "
                   f"{len(extracted_files['images'])} images, "
                   f"{len(extracted_files['videos'])} videos")
        logger.info(f"Structure: Artifacts={bool(extracted_files['structure']['artifacts'])}, "
                   f"Metadata={bool(extracted_files['structure']['metadata'])}, "
                   f"Media={bool(extracted_files['structure']['media'])}")
        return extracted_files
    except zipfile.BadZipFile as e:
        logger.error(f"Invalid ZIP file format: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler
    except MemoryError as e:
        logger.error(f"Memory error extracting ZIP file: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler
    except Exception as e:
        logger.error(f"Failed to extract ZIP file: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler

def normalize_zip_to_ufdr(extracted_files):
    """Convert extracted ZIP structure to UFDR format."""
    try:
        structure = extracted_files.get('structure', {})
        artifacts = structure.get('artifacts', {})
        metadata = structure.get('metadata', {})
        
        # Initialize UFDR structure
        ufdr_data = {
            'contacts': [],
            'messages': [],
            'call_logs': [],
            'device': {},
            'files': []
        }
    except Exception as e:
        logger.error(f"Error initializing UFDR structure: {e}")
        raise
    
    # Map Contacts
    try:
        if 'contacts' in artifacts:
            contacts = artifacts['contacts']
            if isinstance(contacts, list):
                ufdr_data['contacts'] = contacts
            else:
                ufdr_data['contacts'] = [contacts] if contacts else []
    except Exception as e:
        logger.warning(f"Error processing contacts: {e}")
        ufdr_data['contacts'] = []
    
    # Merge SMS and WhatsApp into messages
    messages = []
    try:
        if 'sms' in artifacts:
            sms_messages = artifacts['sms']
            if isinstance(sms_messages, list):
                for msg in sms_messages:
                    # Normalize message format: sender/message -> from/to/text
                    normalized_msg = dict(msg)
                    normalized_msg['source'] = 'SMS'
                    # Map sender -> from, receiver -> to
                    if 'sender' in normalized_msg and 'from' not in normalized_msg:
                        normalized_msg['from'] = normalized_msg['sender']
                    if 'receiver' in normalized_msg and 'to' not in normalized_msg:
                        normalized_msg['to'] = normalized_msg['receiver']
                    # Map content fields: message -> text, or ensure content exists
                    if 'message' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['message']
                    if 'content' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['content']
                    # Ensure at least one content field exists (validation requires text or content)
                    if 'text' not in normalized_msg and 'content' not in normalized_msg:
                        # Try to find any text-like field
                        for field in ['message', 'body', 'content', 'text_content']:
                            if field in normalized_msg and normalized_msg[field]:
                                normalized_msg['text'] = normalized_msg[field]
                                break
                        # If still no content, set empty string (validation checks 'is not None', not truthiness)
                        if 'text' not in normalized_msg:
                            normalized_msg['text'] = ''
                    # If no 'to' field, try to infer or set default
                    if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                        normalized_msg['to'] = 'Unknown'
                    # Ensure 'from' field exists (validation requires parties)
                    if 'from' not in normalized_msg and 'sender' not in normalized_msg:
                        normalized_msg['from'] = 'Unknown'
                    # Map timestamp fields: date, time, datetime -> timestamp
                    if 'timestamp' not in normalized_msg:
                        if 'date' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['date']
                        elif 'time' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['time']
                        elif 'datetime' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['datetime']
                        else:
                            # Add default timestamp if missing (required for validation)
                            normalized_msg['timestamp'] = 'Unknown'
                    messages.append(normalized_msg)
            elif sms_messages:
                normalized_msg = dict(sms_messages)
                normalized_msg['source'] = 'SMS'
                if 'sender' in normalized_msg and 'from' not in normalized_msg:
                    normalized_msg['from'] = normalized_msg['sender']
                if 'message' in normalized_msg and 'text' not in normalized_msg:
                    normalized_msg['text'] = normalized_msg['message']
                if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                    normalized_msg['to'] = 'Unknown'
                # Map timestamp fields
                if 'timestamp' not in normalized_msg:
                    if 'date' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['date']
                    elif 'time' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['time']
                    elif 'datetime' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['datetime']
                    else:
                        normalized_msg['timestamp'] = 'Unknown'
                messages.append(normalized_msg)
        
        if 'whatsapp' in artifacts:
            whatsapp_messages = artifacts['whatsapp']
            if isinstance(whatsapp_messages, list):
                for msg in whatsapp_messages:
                    # Normalize message format: sender/message -> from/to/text
                    normalized_msg = dict(msg)
                    normalized_msg['source'] = 'WhatsApp'
                    # Map sender -> from, receiver -> to
                    if 'sender' in normalized_msg and 'from' not in normalized_msg:
                        normalized_msg['from'] = normalized_msg['sender']
                    if 'receiver' in normalized_msg and 'to' not in normalized_msg:
                        normalized_msg['to'] = normalized_msg['receiver']
                    # Map content fields: message -> text, or ensure content exists
                    if 'message' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['message']
                    if 'content' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['content']
                    # Ensure at least one content field exists (validation requires text or content)
                    if 'text' not in normalized_msg and 'content' not in normalized_msg:
                        # Try to find any text-like field
                        for field in ['message', 'body', 'content', 'text_content']:
                            if field in normalized_msg and normalized_msg[field]:
                                normalized_msg['text'] = normalized_msg[field]
                                break
                        # If still no content, set empty string (validation checks 'is not None', not truthiness)
                        if 'text' not in normalized_msg:
                            normalized_msg['text'] = ''
                    # If no 'to' field, try to infer or set default
                    if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                        normalized_msg['to'] = 'Unknown'
                    # Ensure 'from' field exists (validation requires parties)
                    if 'from' not in normalized_msg and 'sender' not in normalized_msg:
                        normalized_msg['from'] = 'Unknown'
                    # Map timestamp fields: date, time, datetime -> timestamp
                    if 'timestamp' not in normalized_msg:
                        if 'date' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['date']
                        elif 'time' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['time']
                        elif 'datetime' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['datetime']
                        else:
                            # Add default timestamp if missing (required for validation)
                            normalized_msg['timestamp'] = 'Unknown'
                    messages.append(normalized_msg)
            elif whatsapp_messages:
                normalized_msg = dict(whatsapp_messages)
                normalized_msg['source'] = 'WhatsApp'
                if 'sender' in normalized_msg and 'from' not in normalized_msg:
                    normalized_msg['from'] = normalized_msg['sender']
                if 'message' in normalized_msg and 'text' not in normalized_msg:
                    normalized_msg['text'] = normalized_msg['message']
                if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                    normalized_msg['to'] = 'Unknown'
                # Map timestamp fields
                if 'timestamp' not in normalized_msg:
                    if 'date' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['date']
                    elif 'time' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['time']
                    elif 'datetime' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['datetime']
                    else:
                        normalized_msg['timestamp'] = 'Unknown'
                messages.append(normalized_msg)
    except Exception as e:
        logger.warning(f"Error processing messages: {e}")
        # Continue with whatever messages we have
    
    ufdr_data['messages'] = messages
    
    # Map Calls to call_logs and normalize format
    try:
        if 'calls' in artifacts:
            calls = artifacts['calls']
            if isinstance(calls, list):
                normalized_calls = []
                # Get device owner for call normalization
                try:
                    device_owner = metadata.get('device_info', {}).get('owner') or metadata.get('device_info', {}).get('device_owner') or 'Unknown'
                except Exception:
                    device_owner = 'Unknown'
                
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    
                    normalized_call = dict(call)
                    
                    # Convert ZIP format (number, type) to UFDR format (from, to)
                    if 'number' in call and 'type' in call:
                        call_type = call.get('type', '').lower()
                        number = call.get('number', '')
                        
                        if call_type == 'incoming':
                            # Incoming: from = number, to = device owner
                            normalized_call['from'] = number
                            normalized_call['to'] = device_owner
                        elif call_type == 'outgoing':
                            # Outgoing: from = device owner, to = number
                            normalized_call['from'] = device_owner
                            normalized_call['to'] = number
                        elif call_type == 'missed':
                            # Missed: treat as incoming for structure
                            normalized_call['from'] = number
                            normalized_call['to'] = device_owner
                        else:
                            # Unknown type: default to outgoing
                            normalized_call['from'] = device_owner
                            normalized_call['to'] = number
                        
                        # Keep original fields for reference
                        normalized_call['call_type'] = call_type
                        if 'number' not in normalized_call:
                            normalized_call['number'] = number
                    
                    # Ensure timestamp exists
                    if 'timestamp' not in normalized_call:
                        normalized_call['timestamp'] = call.get('timestamp', '')
                    
                    normalized_calls.append(normalized_call)
                
                ufdr_data['call_logs'] = normalized_calls
            else:
                ufdr_data['call_logs'] = [calls] if calls else []
    except Exception as e:
        logger.warning(f"Error processing calls: {e}")
        ufdr_data['call_logs'] = []
    
    # Combine device_info and case_info into device
    device_info = metadata.get('device_info', {})
    case_info = metadata.get('case_info', {})
    
    ufdr_data['device'] = {
        **device_info,
        **case_info,
        'extraction_time': device_info.get('extraction_time', ''),
        'device_model': device_info.get('device_model', ''),
        'imei': device_info.get('imei', ''),
        'device_owner': device_info.get('device_owner') or device_info.get('owner', ''),
        'case_id': case_info.get('case_id', ''),
        'officer': case_info.get('officer', ''),
        'notes': case_info.get('notes', '')
    }
    
    # Map Location data
    try:
        if 'location' in artifacts:
            locations = artifacts['location']
            if isinstance(locations, list):
                ufdr_data['locations'] = locations
            else:
                ufdr_data['locations'] = [locations] if locations else []
            logger.info(f"✅ Processed {len(ufdr_data['locations'])} location records")
    except Exception as e:
        logger.warning(f"Error processing location data: {e}")
        ufdr_data['locations'] = []
    
    # Also check json_files for location data (in case it wasn't in structure)
    try:
        json_files = extracted_files.get('json_files', {})
        for file_path, data in json_files.items():
            if 'Location' in file_path or 'location.json' in file_path:
                if isinstance(data, list):
                    if 'locations' not in ufdr_data or not ufdr_data['locations']:
                        ufdr_data['locations'] = data
                        logger.info(f"✅ Found location data in json_files: {len(data)} records")
                elif data:
                    if 'locations' not in ufdr_data or not ufdr_data['locations']:
                        ufdr_data['locations'] = [data]
                        logger.info(f"✅ Found location data in json_files: 1 record")
                break
    except Exception as e:
        logger.warning(f"Error checking json_files for location data: {e}")
    
    # Add summary if available
    if 'reports' in structure and 'summary' in structure['reports']:
        ufdr_data['summary'] = structure['reports']['summary']
    
    return ufdr_data

def truncate_for_context(text: str, max_tokens: int = 3000, reserved_tokens: int = 1000) -> str:
    """
    Truncate text to fit within model's context window.
    
    Args:
        text: Text to truncate
        max_tokens: Maximum tokens available (default 3000 leaves room for system message and response)
        reserved_tokens: Tokens to reserve for system message, query, and response
    
    Returns:
        Truncated text that fits within context window
    """
    # Rough estimation: 1 token ≈ 2.2 characters for English text
    # More conservative: use 2.0 to be safe
    chars_per_token = 2.0
    available_chars = int((max_tokens - reserved_tokens) * chars_per_token)
    
    if len(text) <= available_chars:
        return text
    
    # Truncate and add indicator
    truncated = text[:available_chars]
    # Try to truncate at a reasonable boundary (end of line or sentence)
    last_newline = truncated.rfind('\n')
    last_period = truncated.rfind('.')
    last_boundary = max(last_newline, last_period)
    
    if last_boundary > available_chars * 0.8:  # If we can find a good boundary
        truncated = text[:last_boundary + 1]
    
    return truncated + f"\n\n[Note: Data truncated to fit context window. Showing first {len(truncated)} characters of {len(text)} total.]"

def prepare_json_for_llm(ufdr_data, query, max_chars=8000):
    """
    Prepare JSON data for LLM to extract directly.
    
    This function sends JSON to the LLM instead of pre-extracted text,
    allowing the LLM to decide what data is relevant to the query.
    
    Args:
        ufdr_data: UFDR data dictionary
        query: User query (used to determine what data to prioritize)
        max_chars: Maximum characters to send (default 8000 ≈ 3000-4000 tokens)
    
    Returns:
        JSON string formatted for LLM consumption
    """
    import json
    
    # Create a copy to modify
    data_copy = dict(ufdr_data)
    
    # Remove internal metadata that LLM doesn't need
    data_copy.pop('_zip_info', None)
    data_copy.pop('_truncated', None)
    
    # Truncate large arrays based on query intent
    query_lower = query.lower() if query else ""
    
    # Determine query intent
    is_contact_query = any(word in query_lower for word in ['contact', 'name', 'phone', 'who', 'people', 'person'])
    is_message_query = any(word in query_lower for word in ['message', 'text', 'sms', 'chat', 'said', 'conversation', 'whatsapp'])
    is_call_query = any(word in query_lower for word in ['call', 'dial', 'phone', 'ring', 'spoke', 'duration'])
    
    # If no specific intent, use balanced limits
    if not any([is_contact_query, is_message_query, is_call_query]):
        is_contact_query = is_message_query = is_call_query = True
    
    # Apply intelligent truncation based on query intent
    # Limit arrays to reasonable sizes to stay within context window
    max_items_per_type = 100  # Reasonable limit per data type
    
    if 'contacts' in data_copy and isinstance(data_copy['contacts'], list):
        if not is_contact_query and len(data_copy['contacts']) > 20:
            data_copy['contacts'] = data_copy['contacts'][:20]
        elif len(data_copy['contacts']) > max_items_per_type:
            data_copy['contacts'] = data_copy['contacts'][:max_items_per_type]
    
    if 'messages' in data_copy and isinstance(data_copy['messages'], list):
        if not is_message_query and len(data_copy['messages']) > 50:
            data_copy['messages'] = data_copy['messages'][:50]
        elif len(data_copy['messages']) > max_items_per_type:
            data_copy['messages'] = data_copy['messages'][:max_items_per_type]
    
    if 'call_logs' in data_copy and isinstance(data_copy['call_logs'], list):
        if not is_call_query and len(data_copy['call_logs']) > 30:
            data_copy['call_logs'] = data_copy['call_logs'][:30]
        elif len(data_copy['call_logs']) > max_items_per_type:
            data_copy['call_logs'] = data_copy['call_logs'][:max_items_per_type]
    
    # Convert to JSON string with proper formatting
    try:
        json_str = json.dumps(data_copy, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        logger.warning(f"Error serializing JSON for LLM: {e}")
        # Fallback: try without ensure_ascii
        json_str = json.dumps(data_copy, indent=2, default=str)
    
    # Apply final truncation if needed
    original_length = len(json_str)
    if len(json_str) > max_chars:
        json_str = truncate_for_context(json_str, max_tokens=3500, reserved_tokens=1000)
        logger.warning(f"⚠️ JSON truncated from {original_length} to {len(json_str)} characters to fit context window")
    
    logger.info(f"Prepared JSON for LLM: {len(json_str)} characters")
    
    return json_str

def has_images_or_videos(data):
    """Check if data contains images or videos that need Qwen2.5-VL processing."""
    if isinstance(data, dict):
        # Check for ZIP info at top level (ACTIVE_DATA structure)
        if '_zip_info' in data:
            zip_info = data.get('_zip_info', {})
            if zip_info.get('is_zip'):
                if zip_info.get('images') or zip_info.get('videos'):
                    logger.info(f"Found images/videos in ZIP: {len(zip_info.get('images', []))} images, {len(zip_info.get('videos', []))} videos")
                    return True
        
        # Check each file's data (if data is a dict of files)
        for key, value in data.items():
            if key == '_zip_info':
                continue
            if isinstance(value, dict):
                # Check for ZIP info in file data
                if '_zip_info' in value:
                    zip_info = value.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        if zip_info.get('images') or zip_info.get('videos'):
                            logger.info(f"Found images/videos in file {key}: {len(zip_info.get('images', []))} images")
                            return True
                
                # Check for image references in messages
                for device in value.get('devices', [value]):
                    # Check messages for image attachments
                    for msg in device.get('messages', []):
                        if not isinstance(msg, dict):
                            continue
                        msg_str = str(msg).lower()
                        if 'image' in msg_str or 'photo' in msg_str:
                            return True
                        if 'attachment' in msg:
                            attachment = msg.get('attachment', '')
                            if attachment and any(ext in str(attachment).lower() 
                                                 for ext in ['.jpg', '.png', '.gif', '.mp4', '.avi']):
                                return True
    return False

def process_with_qwen_vl(query, data_src, chat_history=None):
    """Process query with Qwen2.5-VL-7B for multimodal analysis."""
    if not query:
        return None, "No query provided"
    
    model, processor = init_qwen_vl_model()
    
    if model is None or processor is None:
        return None, "Qwen2.5-VL-7B model not available"
    
    try:
        from PIL import Image
        import torch
        
        # Check for images/videos in ZIP
        # data_src can be a dict of files or a single data structure
        zip_info = {}
        images_to_process = []
        
        # Try to get zip_info from data_src directly (if it's a single data structure)
        if isinstance(data_src, dict) and '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
        else:
            # data_src is a dict of files, check each file's data
            for filename, data in data_src.items():
                if isinstance(data, dict) and '_zip_info' in data:
                    zip_info = data.get('_zip_info', {})
                    break
        
        if zip_info.get('is_zip'):
            # Get images from ZIP
            images_list = zip_info.get('images', [])
            logger.info(f"Found {len(images_list)} images in ZIP file")
            for img_info in images_list[:5]:  # Limit to 5 images
                if not isinstance(img_info, dict):
                    continue
                img_path = img_info.get('path')
                if img_path and os.path.exists(img_path):
                    try:
                        img = Image.open(img_path)
                        images_to_process.append({
                            'image': img,
                            'name': img_info.get('name', 'unknown'),
                            'path': img_path
                        })
                        logger.info(f"Loaded image: {img_info.get('name', 'unknown')}")
                    except Exception as e:
                        logger.warning(f"Failed to load image {img_info.get('name', 'unknown')}: {e}")
                else:
                    logger.warning(f"Image path does not exist: {img_path}")
        
        # If no images found, check query for image-related keywords
        if not images_to_process:
            query_lower = query.lower() if query else ""
            if query_lower and any(word in query_lower for word in ['image', 'photo', 'picture', 'screenshot', 'video']):
                # Try to find images in data
                for filename, data in data_src.items():
                    if filename == '_zip_info':
                        continue
                    # Look for image paths in messages
                    for device in data.get('devices', [data]):
                        for msg in device.get('messages', []):
                            if 'image' in str(msg).lower() or 'photo' in str(msg).lower():
                                # Try to find image file
                                if zip_info.get('is_zip'):
                                    for img_info in zip_info.get('images', []):
                                        if os.path.exists(img_info['path']):
                                            try:
                                                img = Image.open(img_info['path'])
                                                images_to_process.append({
                                                    'image': img,
                                                    'name': img_info['name'],
                                                    'path': img_info['path']
                                                })
                                                break
                                            except:
                                                pass
        
        # Prepare messages for Qwen2.5-VL
        messages = []
        
        if images_to_process:
            # Add images to message - Qwen2.5-VL format
            content = [{"type": "text", "text": query}]
            for img_data in images_to_process:
                content.append({"type": "image", "image": img_data['image']})
            
            messages.append({
                "role": "user",
                "content": content
            })
        else:
            # Text-only query
            messages.append({
                "role": "user",
                "content": query
            })
        
        # Process with Qwen2.5-VL processor
        # Qwen2.5-VL uses messages format with images embedded
        try:
            # Apply chat template (this handles the messages format)
            text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            
            # Extract images from messages
            image_list = []
            if images_to_process:
                image_list = [img_data['image'] for img_data in images_to_process]
            
            # Prepare inputs - Qwen2.5-VL processor accepts text and images separately
            if image_list:
                inputs = processor(
                    text=[text],
                    images=image_list,
                    padding=True,
                    return_tensors="pt"
                ).to(model.device)
            else:
                # Text-only
                inputs = processor(
                    text=[text],
                    padding=True,
                    return_tensors="pt"
                ).to(model.device)
        except Exception as e:
            logger.error(f"Error preparing inputs for Qwen2.5-VL: {e}")
            raise
        
        # Generate response
        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=512, do_sample=False)
        
        # Decode response
        response = processor.batch_decode(outputs, skip_special_tokens=True, clean_up_tokenization_spaces=False)[0]
        
        # Extract just the assistant's response
        if "assistant\n" in response:
            response = response.split("assistant\n")[-1].strip()
        
        return response, None
        
    except Exception as e:
        logger.error(f"Error processing with Qwen2.5-VL: {e}")
        return None, str(e)

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_uploaded_files():
    """Load existing uploaded files into ACTIVE_DATA on startup."""
    global ACTIVE_DATA, ACTIVE_FILENAME, enhanced_nl_engine, ai_retrieval_engine
    
    loaded_count = 0
    if os.path.exists(UPLOAD_FOLDER):
        for filename in os.listdir(UPLOAD_FOLDER):
            # Skip encrypted files (they'll be handled during upload/access)
            if filename.endswith('.encrypted'):
                continue
            if filename.endswith('.json'):
                try:
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        ACTIVE_DATA[filename] = data
                        ACTIVE_FILENAME = filename
                        loaded_count += 1
                        
                        # Update engines with loaded data
                        nl_engine.update_data(ACTIVE_DATA)
                        enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                        ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                        
                except Exception as e:
                    logger.error(f"Error loading {filename}: {e}")
                    continue
    
    return loaded_count

# Authentication helper functions
def get_auth_db_connection():
    """Create and return authentication database connection"""
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Auth database connection error: {e}")
        return None

def load_user_profile_data(user_id=None):
    """Load user profile data from database and update session
    This ensures profile data persists across server restarts, similar to case restoration
    """
    if not user_id:
        user_id = session.get('user_id')
    
    if not user_id:
        return {}
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # First, check which columns exist
        cur.execute("PRAGMA table_info(users)")
        columns_info = cur.fetchall()
        available_columns = [col[1] for col in columns_info]
        
        # Build SELECT query with only existing columns
        base_columns = ['first_name', 'last_name', 'email', 'username']
        optional_columns = ['phone', 'location', 'bio', 'profile_picture']
        
        select_columns = base_columns.copy()
        for col in optional_columns:
            if col in available_columns:
                select_columns.append(col)
        
        # Get all profile fields (only columns that exist)
        query = f"SELECT {', '.join(select_columns)} FROM users WHERE id = ?"
        cur.execute(query, (user_id,))
        user = cur.fetchone()
        
        if user:
            # Row objects don't have .get() method, access directly and handle None
            profile_data = {
                'first_name': user['first_name'] if user['first_name'] else '',
                'last_name': user['last_name'] if user['last_name'] else '',
                'email': user['email'] if user['email'] else '',
                'username': user['username'] if user['username'] else '',
            }
            
            # Add optional fields only if they exist in the result
            for col in optional_columns:
                if col in available_columns:
                    try:
                        profile_data[col] = user[col] if user[col] else ''
                    except (KeyError, IndexError):
                        profile_data[col] = ''
                else:
                    profile_data[col] = ''
            
            # Update session with profile data (ensures persistence)
            session['username'] = profile_data['username']
            session['email'] = profile_data['email']
            session['name'] = f"{profile_data['first_name']} {profile_data['last_name']}".strip()
            session['phone'] = profile_data['phone']
            session['location'] = profile_data['location']
            session['bio'] = profile_data['bio']
            session['profile_picture'] = profile_data['profile_picture']
            
            logger.info(f"Loaded profile data for user {user_id}, profile_picture: {profile_data['profile_picture'] or 'None'}")
            
            cur.close()
            conn.close()
            return profile_data
        else:
            cur.close()
            conn.close()
            return {}
    except Exception as e:
        logger.warning(f"Error loading user profile data: {e}")
        return {}

def login_required(f):
    """Decorator to require login for routes (bypassed in DEV_MODE)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip authentication in development mode
        if DEV_MODE:
            # Set default session values for dev mode
            if 'user_id' not in session:
                session['user_id'] = 1
                session['username'] = 'dev_user'
                session['email'] = 'dev@example.com'
                session['name'] = 'Development User'
            return f(*args, **kwargs)
        
        # Normal authentication check
        if 'user_id' not in session:
            logger.warning(f"Access denied to {request.path}: No user_id in session")
            flash('Please log in to access this page.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def generate_captcha():
    """Generate a simple CAPTCHA"""
    import random
    import string
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    captcha_id = secrets.token_hex(8)
    captcha_storage[captcha_id] = captcha_text
    return captcha_id, captcha_text

def verify_captcha(captcha_id, user_input):
    """Verify CAPTCHA input"""
    if captcha_id not in captcha_storage:
        return False
    stored_captcha = captcha_storage.pop(captcha_id)
    return stored_captcha.upper() == user_input.upper()

@app.route('/auth', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - redirects to Case Manager in DEV_MODE"""
    # If already logged in, redirect to dashboard (prevent redirect loop)
    if 'user_id' in session and not DEV_MODE:
        logger.info(f"User {session.get('user_id')} already logged in, redirecting to dashboard")
        return redirect('/case-manager')
    
    # In development mode, skip login and go straight to Case Manager
    if DEV_MODE:
        # Set default session values for dev mode
        if 'user_id' not in session:
            session['user_id'] = 1
            session['username'] = 'dev_user'
            session['email'] = 'dev@example.com'
            session['name'] = 'Development User'
        return redirect(url_for('case_manager'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        captcha_id = request.form.get('captcha_id', '')
        captcha_input = request.form.get('captcha', '').strip()
        
        if not verify_captcha(captcha_id, captcha_input):
            flash('Invalid CAPTCHA. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        
        conn = get_auth_db_connection()
        if not conn:
            flash('Database connection error.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
            user = cur.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Set session variables
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['name'] = f"{user['first_name']} {user['last_name']}"
                session.permanent = True  # Make session persistent
                
                # Load all profile data from database (phone, location, bio, profile_picture)
                # This ensures profile data persists across server restarts
                try:
                    cur.execute("PRAGMA table_info(users)")
                    columns = [row[1] for row in cur.fetchall()]
                    
                    # Load profile fields if they exist (user is a Row object, access by column name)
                    if 'phone' in columns:
                        session['phone'] = user['phone'] if user['phone'] else ''
                    if 'location' in columns:
                        session['location'] = user['location'] if user['location'] else ''
                    if 'bio' in columns:
                        session['bio'] = user['bio'] if user['bio'] else ''
                    if 'profile_picture' in columns:
                        session['profile_picture'] = user['profile_picture'] if user['profile_picture'] else ''
                        logger.info(f"Loaded profile_picture for user {user['id']}: {session.get('profile_picture', 'None')}")
                except Exception as profile_error:
                    logger.warning(f"Error loading profile data: {profile_error}")
                    # Fallback: try to load profile picture directly
                    try:
                        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user['id'],))
                        pic_row = cur.fetchone()
                        if pic_row and pic_row['profile_picture']:
                            session['profile_picture'] = pic_row['profile_picture']
                            logger.info(f"Loaded profile_picture via fallback: {session.get('profile_picture')}")
                    except Exception as fallback_error:
                        logger.warning(f"Fallback profile picture load failed: {fallback_error}")
                
                # Commit session before redirect
                try:
                    session.modified = True
                except:
                    pass
                
                cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(), user['id']))
                conn.commit()
                
                # Get user role for audit logging
                user_role = 'investigator'  # Default
                if SECURITY_AVAILABLE:
                    try:
                        cur.execute("PRAGMA table_info(users)")
                        columns = [row[1] for row in cur.fetchall()]
                        if 'role' in columns:
                            cur.execute("SELECT role FROM users WHERE id = ?", (user['id'],))
                            role_row = cur.fetchone()
                            if role_row and role_row[0]:
                                user_role = role_row[0]
                    except:
                        pass
                
                cur.close()
                conn.close()
                
                logger.info(f"User {user['email']} (ID: {user['id']}) logged in successfully")
                logger.info(f"Session data: user_id={session.get('user_id')}, username={session.get('username')}")
                
                # Audit logging: Log login event
                if SECURITY_AVAILABLE and audit_logger:
                    audit_logger.log_action('login', resource=f"user_{user['id']}", success=True,
                                          details={
                                              'email': user['email'],
                                              'username': user['username'],
                                              'role': user_role,
                                              'ip_address': request.remote_addr
                                          })
                
                flash('Login successful!', 'success')
                
                # Redirect to Case Manager after login
                return redirect('/case-manager')
            else:
                # Audit logging: Log failed login attempt
                if SECURITY_AVAILABLE and audit_logger:
                    audit_logger.log_action('login', resource=f"email_{email}", success=False,
                                          details={
                                              'reason': 'invalid_credentials',
                                              'ip_address': request.remote_addr
                                          })
                flash('Invalid email or password.', 'error')
                captcha_id, captcha_text = generate_captcha()
                return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
    
    captcha_id, captcha_text = generate_captcha()
    return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)

def validate_password(password):
    """Validate password requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page with password validation"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session and not DEV_MODE:
        return redirect('/case-manager')
    
    if request.method == 'POST':
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')
        terms_accepted = request.form.get('termsCheck') == 'on'
        
        # Validate all fields
        errors = []
        if not first_name:
            errors.append('First name is required')
        if not last_name:
            errors.append('Last name is required')
        if not email or '@' not in email:
            errors.append('Valid email is required')
        if not username or len(username) < 4:
            errors.append('Username must be at least 4 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Validate password requirements
        is_valid, password_error = validate_password(password)
        if not is_valid:
            errors.append(password_error)
        
        if not terms_accepted:
            errors.append('You must accept the terms and conditions')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth.html')
        
        # Check if email or username already exists
        conn = get_auth_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('auth.html')
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email already registered.', 'error')
                cur.close()
                conn.close()
                return render_template('auth.html')
            
            cur.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already taken.', 'error')
                cur.close()
                conn.close()
                return render_template('auth.html')
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert new user - explicitly set role to 'investigator' (default)
            # Check if role column exists
            cur.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cur.fetchall()]
            has_role_column = 'role' in columns
            
            if has_role_column:
                cur.execute("""
                    INSERT INTO users (first_name, last_name, email, username, password_hash, role)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (first_name, last_name, email, username, password_hash, 'investigator'))
            else:
                # Role column doesn't exist yet, insert without it (will be added by migration)
                cur.execute("""
                    INSERT INTO users (first_name, last_name, email, username, password_hash)
                    VALUES (?, ?, ?, ?, ?)
                """, (first_name, last_name, email, username, password_hash))
            
            user_id = cur.lastrowid
            conn.commit()
            
            # Audit logging: Log user creation
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('user_created', resource=f"user_{user_id}", success=True,
                                      details={
                                          'email': email,
                                          'username': username,
                                          'role': 'investigator',
                                          'created_by': 'signup'
                                      })
            
            cur.close()
            conn.close()
            
            logger.info(f"New user created: {email} (ID: {user_id}) with role: investigator")
            flash('Account created successfully! Please log in.', 'success')
            # Redirect to auth page with login tab active
            return redirect('/auth#login')
            
        except Exception as e:
            logger.error(f"Signup error: {e}")
            conn.rollback()
            cur.close()
            conn.close()
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('auth.html')
    
    # GET request - show signup form
    return render_template('auth.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user and clear session"""
    # Audit logging: Log logout event before clearing session
    if SECURITY_AVAILABLE and audit_logger and 'user_id' in session:
        user_id = session.get('user_id')
        username = session.get('username', 'unknown')
        email = session.get('email', 'unknown')
        audit_logger.log_action('logout', resource=f"user_{user_id}", success=True,
                              details={
                                  'email': email,
                                  'username': username,
                                  'ip_address': request.remote_addr
                              })
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def root():
    """Root route - redirects to case manager"""
    return redirect(url_for('case_manager'))

@app.route('/case-manager')
@login_required
def case_manager():
    """Case Manager UI - Main landing page after login"""
    # Debug: Check session
    if 'user_id' not in session:
        logger.warning("No user_id in session when accessing case_manager")
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    logger.info(f"Case manager accessed by user {session.get('user_id')} ({session.get('email')})")
    
    # Get user role for template
    user_role = 'investigator'  # Default
    can_view_audit_logs = False
    can_manage_users = False
    
    if SECURITY_AVAILABLE:
        try:
            user_role = RBAC.get_user_role()
            can_view_audit_logs = RBAC.has_permission('view_audit_logs')
            can_manage_users = RBAC.has_permission('manage_users')
        except Exception as e:
            logger.warning(f"Error getting user role for template: {e}")
    
    # Get user profile data for settings - load from database to ensure persistence across server restarts
    user_id = session.get('user_id')
    user_profile_data = load_user_profile_data(user_id) if user_id else {}
    
    # Ensure all expected fields exist in user_profile_data for template
    if not user_profile_data:
        user_profile_data = {}
    
    # Fill in missing fields from session or set defaults
    user_profile_data.setdefault('first_name', session.get('name', '').split()[0] if session.get('name') else '')
    user_profile_data.setdefault('last_name', session.get('name', '').split()[-1] if len(session.get('name', '').split()) > 1 else '')
    user_profile_data.setdefault('email', session.get('email', ''))
    user_profile_data.setdefault('username', session.get('username', ''))
    user_profile_data.setdefault('phone', session.get('phone', ''))
    user_profile_data.setdefault('location', session.get('location', ''))
    user_profile_data.setdefault('bio', session.get('bio', ''))
    user_profile_data.setdefault('profile_picture', session.get('profile_picture', ''))
    
    # Ensure profile_picture is loaded from session if not in user_profile_data
    profile_picture = user_profile_data.get('profile_picture', '') or session.get('profile_picture', '')
    if not profile_picture and user_id:
        # Last resort: try to load just the profile_picture column
        try:
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Check if profile_picture column exists
            cur.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cur.fetchall()]
            if 'profile_picture' in columns:
                cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
                pic_row = cur.fetchone()
                if pic_row and pic_row['profile_picture']:
                    profile_picture = pic_row['profile_picture']
                    session['profile_picture'] = profile_picture
                    logger.info(f"Loaded profile_picture directly for user {user_id}: {profile_picture}")
            cur.close()
            conn.close()
        except Exception as e:
            logger.warning(f"Error loading profile_picture directly: {e}")
    
    return render_template('case_manager/case_manager.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         first_name=user_profile_data.get('first_name', ''),
                         last_name=user_profile_data.get('last_name', ''),
                         phone=user_profile_data.get('phone', ''),
                         location=user_profile_data.get('location', ''),
                         bio=user_profile_data.get('bio', ''),
                         profile_picture=profile_picture,
                         user_role=user_role,
                         can_view_audit_logs=can_view_audit_logs,
                         can_manage_users=can_manage_users)

@app.route('/evi-scan')
@login_required
def index():
    """Main page with the web interface - requires login (or dev mode)"""
    # Declare global variables at the top of the function
    global ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine
    
    # Check for session_id in URL query params
    session_id_from_url = request.args.get('session_id')
    case_info = None
    
    # Get current user ID for security
    user_id = session.get('user_id')
    
    # Check if this is a brand new session (no chat history) - if so, clear ACTIVE_DATA
    is_new_session = False
    if session_id_from_url and SESSION_DB_AVAILABLE:
        # Restore session from database (filtered by user_id for security)
        sess = get_session(session_id_from_url, user_id=user_id) if user_id else get_session(session_id_from_url)
        if sess:
            # Verify session belongs to current user
            if user_id and sess.get('user_id') != user_id:
                flash('Access denied: This session does not belong to you.', 'error')
                return redirect(url_for('case_manager'))
            # Store in Flask session
            session['session_id'] = session_id_from_url
            case_id = sess.get('case_id')
            if case_id:
                session['case_id'] = case_id
                # Get case information to display in EVI SCAN
                case_info = get_case(case_id)
            # Load chat history from current session AND related sessions (same case)
            # This provides context continuity across multiple sessions for the same case
            chat_history = get_chat_history(session_id_from_url)
            related_chat_history = []
            
            if SESSION_DB_AVAILABLE:
                # Get chat history from related sessions (same case) for context
                related_chat_history = get_chat_history_from_related_sessions(
                    session_id_from_url, 
                    include_current=False,  # Don't duplicate current session's history
                    limit_per_session=50  # Limit per session to avoid token bloat
                )
                logger.info(f"📜 Current session: {len(chat_history)} messages, Related sessions: {len(related_chat_history)} messages")
            
            # Merge histories: related sessions first (chronological), then current session
            # This maintains chronological order while prioritizing current session
            all_chat_history = related_chat_history + chat_history
            
            # Check if session has files in database FIRST (files indicate it's not a brand new session)
            session_files = []
            if SESSION_DB_AVAILABLE:
                session_files = get_session_files(session_id_from_url)
                logger.info(f"📁 Checking session {session_id_from_url}: {len(session_files)} file(s) in database, {len(all_chat_history)} total chat message(s) (current: {len(chat_history)}, related: {len(related_chat_history)})")
            
            # If session has files OR chat history, restore it (it's an existing session)
            if session_files or (all_chat_history and len(all_chat_history) > 0):
                # Existing session - restore uploaded files into ACTIVE_DATA
                logger.info(f"🔄 Restoring existing session {session_id_from_url} - loading session files into ACTIVE_DATA")
                ACTIVE_DATA = {}
                ACTIVE_FILENAME = None
                
                # Load only files that belong to this session
                if session_files and os.path.exists(UPLOAD_FOLDER):
                    loaded_files = []
                    for file_record in session_files:
                        filename = file_record['filename']
                        file_path_recorded = file_record.get('file_path', filename)
                        # Use recorded path or fallback to UPLOAD_FOLDER
                        if os.path.isabs(file_path_recorded) and os.path.exists(file_path_recorded):
                            file_path = file_path_recorded
                        else:
                            file_path = os.path.join(UPLOAD_FOLDER, filename)
                        
                        # Check if file exists (try both encrypted and unencrypted versions)
                        is_encrypted = False
                        original_filename = filename  # Keep original for logging
                        if not os.path.exists(file_path):
                            # Try encrypted version
                            encrypted_path = file_path + '.encrypted'
                            if os.path.exists(encrypted_path):
                                file_path = encrypted_path
                                filename = filename + '.encrypted'  # Update filename to include .encrypted
                                is_encrypted = True
                                logger.info(f"🔐 Found encrypted version: {original_filename} → {filename}")
                                # Update database record to reflect encrypted filename (if session_db available)
                                if SESSION_DB_AVAILABLE and session_id_from_url:
                                    try:
                                        # Delete old record and create new one with encrypted filename
                                        delete_session_file(session_id_from_url, original_filename)
                                        save_session_file(session_id_from_url, filename, file_path)
                                        logger.info(f"📝 Updated database record: {original_filename} → {filename}")
                                    except Exception as db_update_error:
                                        logger.warning(f"⚠️ Could not update database record: {db_update_error}")
                            else:
                                logger.warning(f"File {filename} not found at {file_path} or {encrypted_path}, skipping")
                            continue
                        else:
                            # File exists, check if it's encrypted by checking if filename ends with .encrypted
                            is_encrypted = filename.endswith('.encrypted') or file_path.endswith('.encrypted')
                        
                        try:
                            # Ensure is_encrypted flag is set correctly
                            if not is_encrypted:
                                is_encrypted = file_path.endswith('.encrypted') or filename.endswith('.encrypted')
                            temp_decrypted_path = None
                            
                            # If encrypted, decrypt it first
                            if is_encrypted and SECURITY_AVAILABLE and encryption:
                                try:
                                    logger.info(f"🔓 Decrypting encrypted file: {filename}")
                                    # Read encrypted content
                                    with open(file_path, 'rb') as f:
                                        encrypted_content = f.read()
                                    
                                    # Decrypt content
                                    decrypted_content = encryption.cipher.decrypt(encrypted_content)
                                    
                                    # Create temporary decrypted file for processing
                                    temp_decrypted_path = file_path.replace('.encrypted', '')
                                    with open(temp_decrypted_path, 'wb') as f:
                                        f.write(decrypted_content)
                                    
                                    # Use temp decrypted file for processing
                                    file_path = temp_decrypted_path
                                    logger.info(f"✅ File decrypted for restoration: {filename}")
                                except Exception as decrypt_error:
                                    error_type = type(decrypt_error).__name__
                                    if "InvalidSignature" in error_type or "InvalidToken" in error_type:
                                        logger.error(f"❌ CRITICAL: Cannot decrypt file {filename} - Wrong encryption key!")
                                        logger.error(f"   The encryption key used to encrypt this file is different from the current key.")
                                        logger.error(f"   Possible causes:")
                                        logger.error(f"   1. Encryption key changed between server restarts")
                                        logger.error(f"   2. File was encrypted with a different key")
                                        logger.error(f"   3. File data is corrupted")
                                        logger.error(f"   Solution: Ensure ENCRYPTION_KEY environment variable is set, or restore .encryption_key file")
                                    else:
                                        logger.error(f"❌ Error decrypting file {filename} during restore: {decrypt_error}", exc_info=True)
                                    # Skip this file but continue with others
                                    continue
                            
                            # Handle ZIP files - use hybrid parser (same as upload) for consistent extraction
                            if filename.endswith('.zip') or (is_encrypted and filename.replace('.encrypted', '').endswith('.zip')):
                                try:
                                    logger.info(f"📦 Restoring ZIP file {filename} using hybrid parser...")
                                    
                                    # Check if we have a stored extraction path for this session
                                    stored_extract_path = None
                                    if SESSION_DB_AVAILABLE and session_id_from_url:
                                        try:
                                            sess = get_session(session_id_from_url)
                                            if sess and sess.get('metadata'):
                                                metadata = sess.get('metadata')
                                                if isinstance(metadata, dict):
                                                    stored_extract_path = metadata.get('zip_extraction_path')
                                                    if stored_extract_path and os.path.exists(stored_extract_path):
                                                        logger.info(f"📂 Found stored extraction path: {stored_extract_path}")
                                                    else:
                                                        logger.info(f"⚠️ Stored extraction path does not exist: {stored_extract_path}, will re-extract")
                                        except Exception as meta_error:
                                            logger.debug(f"Could not retrieve stored extraction path: {meta_error}")
                                    
                                    # Use stored path if available and valid, otherwise extract fresh
                                    # Pass session_id to ensure persistent extraction
                                    extracted = extract_zip_with_hybrid_parser(file_path, extract_to=stored_extract_path)
                                    
                                    if extracted:
                                        # Check if hybrid parser already normalized it
                                        if 'hybrid_parsed' in extracted:
                                            # Hybrid parser already normalized, use directly
                                            ufdr_data = extracted['ufdr_data']
                                            logger.info(f"✅ Using hybrid parser normalized data for restore. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                                        else:
                                            # Standard parser - need normalization
                                            ufdr_data = normalize_zip_to_ufdr(extracted)
                                            logger.info(f"✅ Using standard parser normalized data for restore. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                                        
                                        if ufdr_data:
                                            # Store ZIP info with images/videos (same structure as upload)
                                            extract_path = extracted.get('extract_path', '')
                                            zip_info = {
                                                'is_zip': True,
                                                'extracted_path': extract_path,
                                                'images': extracted.get('images', []),
                                                'videos': extracted.get('videos', []),
                                                'json_files': list(extracted.get('json_files', {}).keys()) if isinstance(extracted.get('json_files'), dict) else []
                                            }
                                            logger.info(f"📦 ZIP info for restore: {len(zip_info.get('images', []))} images, {len(zip_info.get('videos', []))} videos, extract_path: {extract_path}")
                                            
                                            # Store extraction path in session metadata for future restores
                                            if SESSION_DB_AVAILABLE and extract_path and session_id_from_url:
                                                try:
                                                    sess = get_session(session_id_from_url)
                                                    if sess:
                                                        metadata = sess.get('metadata', {})
                                                        if not isinstance(metadata, dict):
                                                            metadata = {}
                                                        metadata['zip_extraction_path'] = extract_path
                                                        metadata['zip_filename'] = filename
                                                        # Update session metadata
                                                        import json
                                                        from session_db import create_session
                                                        create_session(session_id_from_url, 
                                                                      case_id=sess.get('case_id'),
                                                                      title=sess.get('title'),
                                                                      metadata=metadata,
                                                                      user_id=sess.get('user_id'))
                                                        logger.info(f"💾 Stored extraction path {extract_path} in session metadata")
                                                except Exception as meta_error:
                                                    logger.debug(f"Could not store extraction path: {meta_error}")
                                            
                                            # Use encrypted filename if file was encrypted, otherwise use original
                                            restore_filename = filename
                                            ACTIVE_DATA[restore_filename] = ufdr_data
                                            ACTIVE_DATA['_zip_info'] = zip_info
                                            ACTIVE_FILENAME = restore_filename
                                            loaded_files.append(restore_filename)
                                            logger.info(f"✅ Restored ZIP file {restore_filename} into ACTIVE_DATA with {len(zip_info.get('images', []))} images")
                                except Exception as zip_error:
                                    logger.error(f"❌ Error extracting/normalizing ZIP file {filename} during restore: {zip_error}", exc_info=True)
                                    # Clean up temp decrypted file if it was created
                                    if temp_decrypted_path and os.path.exists(temp_decrypted_path):
                                        try:
                                            os.remove(temp_decrypted_path)
                                        except:
                                            pass
                                    continue
                            else:
                                # Handle JSON files
                                logger.info(f"📂 Loading file: {filename}")
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    # Normalize the data
                                    data = normalize_ufdr_data(data)
                                    # Use encrypted filename if file was encrypted, otherwise use original
                                    # The filename from database should already include .encrypted if it was encrypted
                                    restore_filename = filename  # Use filename as stored in database (includes .encrypted if encrypted)
                                    ACTIVE_DATA[restore_filename] = data
                                    ACTIVE_FILENAME = restore_filename
                                    loaded_files.append(restore_filename)
                                    logger.info(f"✅ Restored JSON file {restore_filename} into ACTIVE_DATA")
                            
                            # Clean up temporary decrypted file if it was created
                            if temp_decrypted_path and os.path.exists(temp_decrypted_path):
                                try:
                                    os.remove(temp_decrypted_path)
                                    logger.info(f"✅ Cleaned up temp decrypted file after restoration: {temp_decrypted_path}")
                                except Exception as cleanup_error:
                                    logger.warning(f"⚠️ Failed to clean up temp decrypted file {temp_decrypted_path}: {cleanup_error}")
                        except Exception as e:
                            logger.error(f"❌ Error loading file {filename} for session restore: {e}", exc_info=True)
                            continue
                    
                    # Update engines with loaded data
                    if ACTIVE_DATA:
                        try:
                            nl_engine.update_data(ACTIVE_DATA)
                            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                            rebuild_rag_index()
                            logger.info(f"✅ Successfully restored {len(loaded_files)} file(s) into ACTIVE_DATA for session {session_id_from_url}")
                            logger.info(f"   ACTIVE_DATA keys: {list(ACTIVE_DATA.keys())}")
                        except Exception as e:
                            logger.error(f"❌ Error updating engines with restored data: {e}", exc_info=True)
                    else:
                        logger.warning(f"⚠️ No files could be loaded for session {session_id_from_url}")
                elif not session_files:
                    logger.info(f"ℹ️ No files found in database or folder for session {session_id_from_url}")
                else:
                    logger.warning(f"⚠️ UPLOAD_FOLDER does not exist: {UPLOAD_FOLDER}")
            else:
                # Truly new session - no files AND no chat history - clear ACTIVE_DATA
                is_new_session = True
                logger.info(f"🆕 Brand new session {session_id_from_url} detected (no files, no chat) - clearing ACTIVE_DATA")
                ACTIVE_FILENAME = None
                ACTIVE_DATA = {}
                try:
                    nl_engine.update_data(ACTIVE_DATA)
                    enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                    ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                    rebuild_rag_index()
                except Exception as e:
                    logger.error(f"Error clearing ACTIVE_DATA for new session: {e}")
            
            if session_id_from_url not in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id_from_url] = []
            
            # Load all chat history (from related sessions + current session) into in-memory cache
            # This ensures context continuity across sessions for the same case
            for msg in all_chat_history:
                CHAT_HISTORIES[session_id_from_url].append({
                    "role": msg['role'],
                    "content": msg['content'],
                    "timestamp": msg.get('timestamp'),
                    "source_session": msg.get('source_session_id', session_id_from_url)  # Track which session it came from
                })
            
            if related_chat_history:
                logger.info(f"✅ Loaded chat history from {len(set(msg.get('source_session_id', '') for msg in related_chat_history))} previous session(s) for context continuity")
            update_session_access(session_id_from_url)
            # Also update the case's updated_at timestamp when EVI SCAN is accessed
            # This makes "Last Updated" and "Last Opened" synchronized
            if case_id and SESSION_DB_AVAILABLE:
                # update_case already imported at top
                update_case(case_id)  # This will update updated_at to current time
    elif not session_id_from_url:
        # No session_id - this is a fresh start, clear everything
        logger.info("No session_id provided - clearing ACTIVE_DATA for fresh start")
        ACTIVE_FILENAME = None
        ACTIVE_DATA = {}
        try:
            nl_engine.update_data(ACTIVE_DATA)
            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
            rebuild_rag_index()
        except Exception as e:
            logger.error(f"Error clearing ACTIVE_DATA: {e}")
    
    # Get user profile picture
    profile_picture = session.get('profile_picture', '')
    if not profile_picture and user_id:
        try:
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
            user = cur.fetchone()
            if user and user['profile_picture']:
                profile_picture = user['profile_picture']
                session['profile_picture'] = profile_picture
            cur.close()
            conn.close()
        except Exception as e:
            logger.warning(f"Error loading profile picture: {e}")
    
    # In dev mode, show dev user info
    if DEV_MODE:
        return render_template('enhanced_index.html',
                             username='dev_user',
                             name='Development User',
                             email='dev@example.com',
                             profile_picture='',
                             session_id=session_id_from_url or session.get('session_id'),
                             case_id=case_info.get('case_id') if case_info else None,
                             case_name=case_info.get('case_name') if case_info else None)
    return render_template('enhanced_index.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         profile_picture=profile_picture,
                         session_id=session_id_from_url or session.get('session_id'),
                         case_id=case_info.get('case_id') if case_info else None,
                         case_name=case_info.get('case_name') if case_info else None)


@app.route('/images')
@login_required
def images_gallery():
    """Images gallery page for viewing images from ZIP UFDR files."""
    # Get user profile picture - load from database to ensure persistence
    user_id = session.get('user_id')
    profile_picture = session.get('profile_picture', '')
    if not profile_picture and user_id:
        # Load profile data from database (ensures persistence across server restarts)
        profile_data = load_user_profile_data(user_id)
        profile_picture = profile_data.get('profile_picture', '') if profile_data else ''
    
    return render_template('images_gallery.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         profile_picture=profile_picture)


def validate_ufdr_structure(file_data):
    """
    Comprehensive UFDR file structure validation.
    Supports both v1 (flat structure) and v2 (devices array) formats.
    
    Args:
        file_data: The UFDR file data to validate
        
    Returns:
        Dictionary containing validation results
    """
    # Check if this is v2 format with devices array
    if 'devices' in file_data and isinstance(file_data['devices'], list):
        # V2 format validation
        if len(file_data['devices']) == 0:
            return {'is_valid': False, 'message': 'V2 format: devices array is empty'}
        
        validation_errors = []
        
        for device_idx, device_entry in enumerate(file_data['devices']):
            if not isinstance(device_entry, dict):
                validation_errors.append(f'Device {device_idx} is not a dictionary')
                continue
            
            # Validate contacts within this device
            device_contacts = device_entry.get('contacts', [])
            if device_contacts is not None and not isinstance(device_contacts, list):
                validation_errors.append(f'Device {device_idx}: contacts (not a list)')
                continue
            
            if isinstance(device_contacts, list):
                for i, contact in enumerate(device_contacts):
                    if not isinstance(contact, dict):
                        validation_errors.append(f'Device {device_idx}, Contact {i} is not a dictionary')
                        continue
                    if not (contact.get('name') or contact.get('phone')):
                        validation_errors.append(f'Device {device_idx}, Contact {i} missing name/phone')
            
            # Validate messages within this device
            device_messages = device_entry.get('messages', [])
            if device_messages is not None and not isinstance(device_messages, list):
                validation_errors.append(f'Device {device_idx}: messages (not a list)')
                continue
            
            if isinstance(device_messages, list):
                for i, message in enumerate(device_messages):
                    if not isinstance(message, dict):
                        validation_errors.append(f'Device {device_idx}, Message {i} is not a dictionary')
                        continue
                    
                    has_parties = (message.get('from') and message.get('to')) or (message.get('sender') and message.get('receiver'))
                    has_content = (message.get('text') is not None) or (message.get('content') is not None)
                    has_timestamp = bool(message.get('timestamp'))
                    if not (has_parties and has_content and has_timestamp):
                        validation_errors.append(f'Device {device_idx}, Message {i} missing required fields')
            
            # Validate calls within this device
            device_calls = device_entry.get('call_logs', device_entry.get('calls', []))
            if device_calls is not None and not isinstance(device_calls, list):
                validation_errors.append(f'Device {device_idx}: call_logs/calls (not a list)')
                continue
            
            if isinstance(device_calls, list):
                for i, call in enumerate(device_calls):
                    if not isinstance(call, dict):
                        validation_errors.append(f'Device {device_idx}, Call {i} is not a dictionary')
                        continue
                    
                    has_parties = (call.get('from') and call.get('to')) or (call.get('caller') and call.get('receiver'))
                    has_timestamp = bool(call.get('timestamp'))
                    if not (has_parties and has_timestamp):
                        validation_errors.append(f'Device {device_idx}, Call {i} missing required fields')
        
        if validation_errors:
            return {
                'is_valid': False,
                'message': f'V2 validation errors: {"; ".join(validation_errors[:5])}{"..." if len(validation_errors) > 5 else ""}'
            }
        
        return {
            'is_valid': True,
            'message': f'V2 UFDR file structure is valid ({len(file_data["devices"])} devices)'
        }
    
    # V1 format validation (original logic)
    # Normalize sections: accept keys from multiple schema variants
    contacts = file_data.get('contacts', [])
    messages = file_data.get('messages', [])
    calls = file_data.get('call_logs', file_data.get('calls', []))
    
    # Basic type checks if sections exist
    if contacts is not None and not isinstance(contacts, list):
        return {'is_valid': False, 'message': 'contacts (not a list)'}
    if messages is not None and not isinstance(messages, list):
        return {'is_valid': False, 'message': 'messages (not a list)'}
    if calls is not None and not isinstance(calls, list):
        return {'is_valid': False, 'message': 'calls/call_logs (not a list)'}
    
    # Validate individual data structures
    validation_errors = []
    
    # Validate contacts
    if isinstance(contacts, list):
        for i, contact in enumerate(contacts):
            if not isinstance(contact, dict):
                validation_errors.append(f'Contact {i} is not a dictionary')
                continue
            
            # Accept minimal fields; name or phone preferred
            if not (contact.get('name') or contact.get('phone')):
                validation_errors.append(f'Contact {i} missing name/phone')
    
    # Validate messages
    if isinstance(messages, list):
        for i, message in enumerate(messages):
            if not isinstance(message, dict):
                validation_errors.append(f'Message {i} is not a dictionary')
                continue
            
            # Accept either (from/to/text) or (sender/receiver/content), plus timestamp
            has_parties = (message.get('from') and message.get('to')) or (message.get('sender') and message.get('receiver'))
            has_content = (message.get('text') is not None) or (message.get('content') is not None)
            has_timestamp = bool(message.get('timestamp'))
            if not (has_parties and has_content and has_timestamp):
                validation_errors.append(f'Message {i} missing required fields (parties/content/timestamp)')
    
    # Validate calls (calls or call_logs)
    if isinstance(calls, list):
        for i, call in enumerate(calls):
            if not isinstance(call, dict):
                validation_errors.append(f'Call {i} is not a dictionary')
                continue
            
            has_parties = (call.get('from') and call.get('to')) or (call.get('caller') and call.get('receiver'))
            has_timestamp = bool(call.get('timestamp'))
            if not (has_parties and has_timestamp):
                validation_errors.append(f'Call {i} missing required fields (parties/timestamp)')
    
    if validation_errors:
        return {
            'is_valid': False,
            'message': f'V1 validation errors: {"; ".join(validation_errors[:5])}{"..." if len(validation_errors) > 5 else ""}'
        }
    
    # Consider valid even if sections are missing; caller may warn separately
    return {
        'is_valid': True,
        'message': 'V1 UFDR file structure is valid'
    }

def normalize_ufdr_data(raw: dict) -> dict:
    """Normalize various UFDR schemas into a standard app schema.
    Ensures presence of: contacts, messages, call_logs, files, device.
    Maps common alternate keys to expected ones.
    Supports both v1 (flat structure) and v2 (devices array) formats.
    """
    data = dict(raw) if isinstance(raw, dict) else {}
    if not isinstance(data, dict):
        return {'contacts': [], 'messages': [], 'call_logs': [], 'files': [], 'device': {}}

    # Check if this is v2 format with devices array
    if 'devices' in data and isinstance(data['devices'], list) and len(data['devices']) > 0:
        # V2 format: aggregate data from all devices
        all_contacts = []
        all_messages = []
        all_calls = []
        all_files = []
        all_locations = []
        primary_device = {}
        
        for device_entry in data['devices']:
            if not isinstance(device_entry, dict):
                continue
                
            # Collect contacts
            device_contacts = device_entry.get('contacts', [])
            if isinstance(device_contacts, list):
                all_contacts.extend(device_contacts)
            
            # Collect messages
            device_messages = device_entry.get('messages', [])
            if isinstance(device_messages, list):
                for m in device_messages:
                    if isinstance(m, dict):
                        nm = dict(m)
                        if 'from' not in nm and 'sender' in nm:
                            nm['from'] = nm.get('sender')
                        if 'to' not in nm and 'receiver' in nm:
                            nm['to'] = nm.get('receiver')
                        if 'text' not in nm and 'content' in nm:
                            nm['text'] = nm.get('content')
                        all_messages.append(nm)
            
            # Collect calls
            device_calls = device_entry.get('call_logs', device_entry.get('calls', []))
            if isinstance(device_calls, list):
                for c in device_calls:
                    if isinstance(c, dict):
                        nc = dict(c)
                        if 'from' not in nc and 'caller' in nc:
                            nc['from'] = nc.get('caller')
                        if 'to' not in nc and 'receiver' in nc:
                            nc['to'] = nc.get('receiver')
                        if 'duration' not in nc and 'duration_seconds' in nc:
                            nc['duration'] = nc.get('duration_seconds')
                        all_calls.append(nc)
            
            # Collect files
            device_files = device_entry.get('files', [])
            if isinstance(device_files, list):
                all_files.extend(device_files)
            
            # Collect locations
            device_locations = device_entry.get('locations', [])
            if isinstance(device_locations, list):
                all_locations.extend(device_locations)
            
            # Use first device info as primary
            if not primary_device and 'device' in device_entry:
                primary_device = device_entry['device']
        
        return {
            'contacts': all_contacts,
            'messages': all_messages,
            'call_logs': all_calls,
            'files': all_files,
            'locations': all_locations,
            'device': primary_device,
            'tampered': data.get('tampered', False),
            'tampered_reason': data.get('tampered_reason'),
            'format_version': 'v2',
            'device_count': len(data['devices'])
        }
    
    # V1 format processing (original logic)
    # Contacts
    contacts = data.get('contacts')
    if not isinstance(contacts, list):
        contacts = []

    # Messages normalize
    normalized_messages = []
    src_messages = data.get('messages') if isinstance(data.get('messages'), list) else []
    for m in src_messages:
        if not isinstance(m, dict):
            continue
        nm = dict(m)
        if 'from' not in nm and 'sender' in nm:
            nm['from'] = nm.get('sender')
        if 'to' not in nm and 'receiver' in nm:
            nm['to'] = nm.get('receiver')
        if 'text' not in nm and 'content' in nm:
            nm['text'] = nm.get('content')
        normalized_messages.append(nm)

    # Fallback: collect nested message-like entries
    if not normalized_messages:
        def _collect_messages(node):
            acc = []
            if isinstance(node, list):
                for itm in node:
                    if isinstance(itm, dict):
                        keys = set(itm.keys())
                        if 'timestamp' in keys and (('text' in keys) or ('content' in keys)) and (('from' in keys and 'to' in keys) or ('sender' in keys and 'receiver' in keys)):
                            nm = dict(itm)
                            if 'from' not in nm and 'sender' in nm:
                                nm['from'] = nm.get('sender')
                            if 'to' not in nm and 'receiver' in nm:
                                nm['to'] = nm.get('receiver')
                            if 'text' not in nm and 'content' in nm:
                                nm['text'] = nm.get('content')
                            acc.append(nm)
            elif isinstance(node, dict):
                for v in node.values():
                    acc.extend(_collect_messages(v))
            return acc
        normalized_messages = _collect_messages(data)

    # Calls normalize: prefer call_logs else calls
    src_calls = data.get('call_logs')
    if not isinstance(src_calls, list):
        src_calls = data.get('calls') if isinstance(data.get('calls'), list) else []
    normalized_calls = []
    for c in src_calls:
        if not isinstance(c, dict):
            continue
        nc = dict(c)
        if 'from' not in nc and 'caller' in nc:
            nc['from'] = nc.get('caller')
        if 'to' not in nc and 'receiver' in nc:
            nc['to'] = nc.get('receiver')
        if 'duration' not in nc and 'duration_seconds' in nc:
            nc['duration'] = nc.get('duration_seconds')
        normalized_calls.append(nc)

    # Fallback: collect nested call-like entries
    if not normalized_calls:
        def _collect_calls(node):
            acc = []
            if isinstance(node, list):
                for itm in node:
                    if isinstance(itm, dict):
                        keys = set(itm.keys())
                        if 'timestamp' in keys and (('from' in keys and 'to' in keys) or ('caller' in keys and 'receiver' in keys)):
                            nc = dict(itm)
                            if 'from' not in nc and 'caller' in nc:
                                nc['from'] = nc.get('caller')
                            if 'to' not in nc and 'receiver' in nc:
                                nc['to'] = nc.get('receiver')
                            if 'duration' not in nc and 'duration_seconds' in nc:
                                nc['duration'] = nc.get('duration_seconds')
                            acc.append(nc)
            elif isinstance(node, dict):
                for v in node.values():
                    acc.extend(_collect_calls(v))
            return acc
        normalized_calls = _collect_calls(data)

    # Files
    files = data.get('files') if isinstance(data.get('files'), list) else []

    # Locations
    locations = data.get('locations', [])
    if not isinstance(locations, list):
        locations = []

    # Device
    device = data.get('device') if isinstance(data.get('device'), dict) else {}

    return {
        'contacts': contacts,
        'messages': normalized_messages,
        'call_logs': normalized_calls,
        'files': files,
        'locations': locations,
        'device': device,
        'tampered': data.get('tampered', False),
        'tampered_reason': data.get('tampered_reason'),
        'format_version': 'v1'
    }

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "OK", "message": "Server is running"}), 200

@app.route('/api/upload', methods=['GET', 'POST'])
def upload_file():
    """Upload UFDR JSON files with comprehensive validation."""
    # Handle GET requests with helpful error message
    if request.method == 'GET':
        return jsonify({
            "status": "ERROR",
            "message": "This endpoint only accepts POST requests. Please use the file upload interface on the main page to upload files."
        }), 405
    
    logger.info("=" * 50)
    logger.info("Upload request received")
    try:
        if 'file' not in request.files:
            logger.warning("No file in request")
            return jsonify({"status": "ERROR", "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("Empty filename")
            return jsonify({"status": "ERROR", "message": "No file selected"}), 400
        
        logger.info(f"File received: {file.filename}")
        
        # Check file extension
        if not file or not allowed_file(file.filename):
            return jsonify({"status": "ERROR", "message": "Only JSON and ZIP files are allowed"})
        
        # Check file size (limit to 10GB)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 10 * 1024 * 1024 * 1024:  # 10GB limit
            return jsonify({"status": "ERROR", "message": "File size exceeds 10GB limit"})
        
        if file_size == 0:
            return jsonify({"status": "ERROR", "message": "File is empty"})
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        encrypted_filepath = filepath + '.encrypted'
        
        # Check if file already exists (both encrypted and unencrypted versions) - allow overwriting
        files_to_remove = []
        if os.path.exists(filepath):
            files_to_remove.append(filepath)
        if os.path.exists(encrypted_filepath):
            files_to_remove.append(encrypted_filepath)
        
        if files_to_remove:
            logger.info(f"File {filename} already exists. Removing old file(s) to allow overwrite.")
            for file_to_remove in files_to_remove:
                try:
                    os.remove(file_to_remove)
                    logger.info(f"Removed existing file: {file_to_remove}")
                except Exception as e:
                    logger.warning(f"Failed to remove existing file {file_to_remove}: {e}")
                    return jsonify({"status": "ERROR", "message": f"File '{filename}' already exists and could not be removed. Please manually delete it first."})
        
        # Save file with error handling
        try:
            file.save(filepath)
            logger.info(f"File saved successfully: {filename} ({file_size} bytes)")
            
            # Encrypt file if security is available
            if SECURITY_AVAILABLE and encryption:
                try:
                    # Read file content
                    with open(filepath, 'rb') as f:
                        file_content = f.read()
                    
                    # Encrypt file content
                    encrypted_content = encryption.cipher.encrypt(file_content)
                    
                    # Save encrypted file (append .encrypted extension)
                    encrypted_filepath = filepath + '.encrypted'
                    with open(encrypted_filepath, 'wb') as f:
                        f.write(encrypted_content)
                    
                    # Remove original unencrypted file
                    os.remove(filepath)
                    
                    # Update filepath to encrypted version
                    filepath = encrypted_filepath
                    logger.info(f"File encrypted successfully: {filename}")
                except Exception as e:
                    logger.warning(f"File encryption failed, keeping unencrypted: {e}")
                    # Continue with unencrypted file if encryption fails
            
            # Calculate file hash for integrity checking
            file_hash = None
            if SECURITY_AVAILABLE:
                try:
                    file_hash = calculate_file_hash(filepath)
                    logger.info(f"File hash calculated: {file_hash[:16]}...")
                except Exception as e:
                    logger.warning(f"Could not calculate file hash: {e}")
            
            # Audit logging for file upload
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('file_upload', resource=filename, success=True,
                                      details={'size': file_size, 'hash': file_hash[:32] if file_hash else None})
        except Exception as e:
            logger.error(f"Error saving file {filename}: {str(e)}", exc_info=True)
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('file_upload', resource=filename, success=False,
                                      details={'error': str(e)})
            return jsonify({
                "status": "ERROR",
                "message": f"Failed to save file: {str(e)}. The file might be too large or there's insufficient disk space."
            }), 500
        
        # Handle encrypted files - decrypt if needed
        is_encrypted = filepath.endswith('.encrypted')
        temp_decrypted_file = None  # Track temp file for cleanup
        original_encrypted_filepath = None  # Keep reference to encrypted file
        
        if is_encrypted and SECURITY_AVAILABLE and encryption:
            try:
                # Store reference to original encrypted file
                original_encrypted_filepath = filepath
                
                # Read encrypted content
                with open(filepath, 'rb') as f:
                    encrypted_content = f.read()
                
                # Decrypt content
                decrypted_content = encryption.cipher.decrypt(encrypted_content)
                
                # Create temporary decrypted file for processing
                temp_filepath = filepath.replace('.encrypted', '')
                with open(temp_filepath, 'wb') as f:
                    f.write(decrypted_content)
                
                temp_decrypted_file = temp_filepath  # Track for cleanup
                filepath = temp_filepath
                logger.info(f"File decrypted for processing: {filename}")
            except Exception as e:
                logger.error(f"Error decrypting file: {e}")
                return jsonify({"status": "ERROR", "message": f"Failed to decrypt file: {str(e)}"}), 500
        
        # Handle ZIP files
        if filename.endswith('.zip') or (is_encrypted and filename.replace('.encrypted', '').endswith('.zip')):
            logger.info(f"Processing ZIP file: {filename} (size: {file_size} bytes)")
            logger.info("Starting ZIP file extraction with hybrid parser...")
            try:
                # Try hybrid parser first (heuristics + LLM fallback)
                extracted = extract_zip_with_hybrid_parser(filepath)
                logger.info(f"ZIP extraction complete. JSON files: {len(extracted.get('json_files', {}))}, Images: {len(extracted.get('images', []))}")
            except MemoryError as e:
                logger.error(f"Memory error extracting ZIP file: {str(e)}", exc_info=True)
                try:
                    # Remove temp decrypted file if it exists, keep encrypted file
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({
                    "status": "ERROR",
                    "message": "ZIP file is too large to process. The server ran out of memory. Please try a smaller file or split the ZIP into smaller parts."
                }), 500
            except zipfile.BadZipFile as e:
                logger.error(f"Invalid ZIP file format: {str(e)}", exc_info=True)
                try:
                    # Remove temp decrypted file if it exists, keep encrypted file
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({
                    "status": "ERROR",
                    "message": "Invalid ZIP file format. Please ensure the file is a valid ZIP archive."
                }), 400
            except Exception as e:
                logger.error(f"Error extracting ZIP file: {str(e)}", exc_info=True)
                try:
                    # Remove temp decrypted file if it exists, keep encrypted file
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                error_msg = str(e)
                if "corrupted" in error_msg.lower() or "bad zip" in error_msg.lower():
                    return jsonify({
                        "status": "ERROR",
                        "message": "ZIP file appears to be corrupted or invalid. Please check the file and try again."
                    }), 400
                return jsonify({
                    "status": "ERROR",
                    "message": f"Failed to extract ZIP file: {error_msg}"
                }), 500
            
            if not extracted:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({
                    "status": "ERROR",
                    "message": "Failed to extract ZIP file"
                })
            
            # Check if we have the expected UFDR structure
            structure = extracted.get('structure', {})
            has_artifacts = bool(structure.get('artifacts'))
            has_metadata = bool(structure.get('metadata'))
            
            if not has_artifacts and not extracted.get('json_files'):
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                # Provide more helpful error message
                structure_info = f"Found: {len(extracted.get('json_files', {}))} JSON files"
                return jsonify({
                    "status": "ERROR",
                    "message": f"ZIP file does not contain valid UFDR structure. Expected 'Artifacts/' folder with Calls, Contacts, SMS, and WhatsApp JSON files. {structure_info}"
                })
            
            # Normalize ZIP structure to UFDR format
            # Check if hybrid parser already normalized it
            if 'hybrid_parsed' in extracted:
                # Hybrid parser already normalized, use directly
                ufdr_data = extracted['ufdr_data']
                logger.info(f"Using hybrid parser normalized data. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
            else:
                # Standard parser - need normalization
                try:
                    logger.info("Starting ZIP normalization...")
                    ufdr_data = normalize_zip_to_ufdr(extracted)
                    logger.info(f"Normalization complete. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                except Exception as e:
                    logger.error(f"Error normalizing ZIP data: {str(e)}", exc_info=True)
                    # Remove temp decrypted file if it exists, keep encrypted file
                    try:
                        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                            os.remove(temp_decrypted_file)
                        elif not is_encrypted and os.path.exists(filepath):
                            os.remove(filepath)
                    except:
                        pass
                    return jsonify({
                        "status": "ERROR",
                        "message": f"Error processing ZIP file structure: {str(e)}. Please check the file format."
                    }), 500
            
            if not ufdr_data or (not ufdr_data.get('contacts') and not ufdr_data.get('messages') 
                                and not ufdr_data.get('call_logs')):
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                # Provide detailed error message
                found_items = []
                if ufdr_data:
                    if ufdr_data.get('contacts'):
                        found_items.append(f"{len(ufdr_data.get('contacts'))} contacts")
                    if ufdr_data.get('messages'):
                        found_items.append(f"{len(ufdr_data.get('messages'))} messages")
                    if ufdr_data.get('call_logs'):
                        found_items.append(f"{len(ufdr_data.get('call_logs'))} calls")
                
                found_str = f"Found: {', '.join(found_items)}" if found_items else "No data found"
                return jsonify({
                    "status": "ERROR",
                    "message": f"ZIP file does not contain valid UFDR data. Expected Artifacts folder with Calls, Contacts, SMS, and WhatsApp JSON files. {found_str}"
                })
            
            # Use normalized UFDR data
            # If hybrid parser already normalized it, use directly without re-normalizing
            if 'hybrid_parsed' in extracted:
                # Hybrid parser already normalized the data, use it directly
                data = ufdr_data
                logger.info(f"Using hybrid parser normalized data directly (skipping re-normalization)")
            else:
                # Standard parser - need to normalize
                raw = ufdr_data
                data = normalize_ufdr_data(raw)
            
            zip_info = {
                'is_zip': True,
                'extracted_path': extracted.get('extract_path', ''),
                'images': extracted.get('images', []),
                'videos': extracted.get('videos', []),
                'json_files': list(extracted.get('json_files', {}).keys())
            }
            # Log image/video counts for debugging
            # Log image/video counts for debugging
            image_count = len(zip_info.get('images', []))
            video_count = len(zip_info.get('videos', []))
            logger.info(f"ZIP info created: {image_count} images, {video_count} videos")
            if image_count == 0 and video_count == 0:
                logger.warning(f"⚠️ No images/videos found in extracted data. Extracted keys: {list(extracted.keys())}")
                if 'images' in extracted:
                    logger.warning(f"   extracted['images'] type: {type(extracted.get('images'))}, length: {len(extracted.get('images', []))}")
                if 'videos' in extracted:
                    logger.warning(f"   extracted['videos'] type: {type(extracted.get('videos'))}, length: {len(extracted.get('videos', []))}")
        else:
            # Handle JSON files (existing logic)
            zip_info = {'is_zip': False}
            # Validate JSON format and UFDR structure
            try:
                # Read file (already decrypted if encrypted)
                with open(filepath, 'r', encoding='utf-8') as f:
                    raw = json.load(f)
            except json.JSONDecodeError as e:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({"status": "ERROR", "message": f"Invalid JSON format: {str(e)}"})
            
            # Normalize uploaded data to SYNTHETIC UFDR schema (for JSON files)
            try:
                data = normalize_ufdr_data(raw)
            except Exception as e:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({"status": "ERROR", "message": f"Failed to normalize UFDR data: {str(e)}"})
        
        # Basic JSON structure check
        if not isinstance(data, dict):
            # Remove temp decrypted file if it exists, keep encrypted file
            try:
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    os.remove(temp_decrypted_file)
                elif not is_encrypted and os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
            return jsonify({"status": "ERROR", "message": "Invalid JSON format: root element must be an object"})
        
        # Comprehensive UFDR validation
        validation_result = validate_ufdr_structure(data)
        
        if not validation_result['is_valid']:
            # Remove temp decrypted file if it exists, keep encrypted file
            try:
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    os.remove(temp_decrypted_file)
                elif not is_encrypted and os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
            return jsonify({
                "status": "ERROR", 
                "message": f"Invalid UFDR file structure: {validation_result['message']}"
            })
        
        # Additional checks for data quality
        warnings = []
        
        # Section presence and emptiness warnings (supporting v2 keys)
        if 'contacts' not in data:
            warnings.append("'contacts' section missing")
        elif len(data.get('contacts', [])) == 0:
            warnings.append("'contacts' section is empty")
        
        if 'messages' not in data:
            warnings.append("'messages' section missing")
        elif len(data.get('messages', [])) == 0:
            warnings.append("'messages' section is empty")
        
        if 'call_logs' not in data and 'calls' not in data:
            warnings.append("'call_logs'/'calls' section missing")
        else:
            calls_list = data.get('call_logs', data.get('calls', []))
            if isinstance(calls_list, list) and len(calls_list) == 0:
                warnings.append("'call_logs'/'calls' section is empty")
        
        if 'device' not in data:
            warnings.append("Missing device information")
        
        # Set this file as ACTIVE context only
        # Use encrypted filename if file was encrypted, otherwise use original
        global ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine
        active_filename = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename
        ACTIVE_FILENAME = active_filename
        ACTIVE_DATA = {active_filename: data}
        # Store ZIP info if it's a ZIP file
        if zip_info.get('is_zip'):
            ACTIVE_DATA['_zip_info'] = zip_info
            
            # Save extraction path to session metadata for persistence
            if SESSION_DB_AVAILABLE:
                session_id = session.get('session_id')
                if session_id and session_id != 'None' and session_id != '':
                    extract_path = zip_info.get('extracted_path', '')
                    if extract_path:
                        # Store extraction path in session metadata
                        try:
                            sess = get_session(session_id)
                            if sess:
                                metadata = sess.get('metadata', {})
                                if not isinstance(metadata, dict):
                                    metadata = {}
                                metadata['zip_extraction_path'] = extract_path
                                metadata['zip_filename'] = active_filename
                                # Update session with metadata
                                import json
                                from session_db import update_session_access
                                # We need to update the session metadata
                                # For now, we'll store it in a way that can be retrieved
                                logger.info(f"💾 Storing extraction path {extract_path} for session {session_id}")
                        except Exception as meta_error:
                            logger.warning(f"Could not store extraction path in metadata: {meta_error}")
        
        # Save file to session_files table if we have a session_id
        # Try multiple sources for session_id
        session_id = None
        if SESSION_DB_AVAILABLE:
            # Try Flask session first
            session_id = session.get('session_id')
            # Try URL params if not in session
            if not session_id or session_id == 'None' or session_id == '':
                session_id = request.args.get('session_id')
            # Try request form data
            if not session_id or session_id == 'None' or session_id == '':
                session_id = request.form.get('session_id')
            # Try JSON body
            if not session_id or session_id == 'None' or session_id == '':
                try:
                    json_data = request.get_json(silent=True)
                    if json_data:
                        session_id = json_data.get('session_id')
                except:
                    pass
            
            if session_id and session_id != 'None' and session_id != '':
                # Use encrypted filename if file was encrypted, otherwise use original
                file_to_save = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename
                file_path_full = os.path.join(UPLOAD_FOLDER, file_to_save)
                if save_session_file(session_id, file_to_save, file_path_full):
                    logger.info(f"✅ Saved file {file_to_save} to session {session_id} in database")
                    # Also store in Flask session for future use
                    session['session_id'] = session_id
                else:
                    logger.warning(f"❌ Failed to save file {file_to_save} to session {session_id}")
            else:
                logger.warning(f"⚠️ No session_id available when uploading {filename}. File not linked to session.")
        
        # Log data structure for debugging
        logger.info(f"Storing data for {filename}: contacts={len(data.get('contacts', []))}, messages={len(data.get('messages', []))}, calls={len(data.get('call_logs', []))}")
        logger.info(f"ACTIVE_DATA keys: {list(ACTIVE_DATA.keys())}")
        
        # Update engines with new data (synchronously to avoid race conditions)
        try:
            nl_engine.update_data(ACTIVE_DATA)
            logger.info("Updated nl_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error updating nl_engine: {e}", exc_info=True)
        
        # Initialize enhanced engine with new data
        try:
            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
            logger.info("Initialized enhanced_nl_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error initializing enhanced_nl_engine: {e}", exc_info=True)
        
        # Initialize AI retrieval engine with new data
        try:
            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
            logger.info("Initialized ai_retrieval_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error initializing ai_retrieval_engine: {e}", exc_info=True)
        
        # Prepare quick stats for immediate UI update
        # Ensure we're working with lists and handle both formats
        contacts_list = data.get("contacts", [])
        messages_list = data.get("messages", [])
        calls_list = data.get("call_logs", data.get("calls", []))
        
        # Handle V2 format with devices array
        if not isinstance(contacts_list, list) or len(contacts_list) == 0:
            devices = data.get("devices", [])
            if devices and isinstance(devices, list):
                contacts_list = []
                messages_list = []
                calls_list = []
                for device in devices:
                    if isinstance(device, dict):
                        contacts_list.extend(device.get("contacts", []))
                        messages_list.extend(device.get("messages", []))
                        calls_list.extend(device.get("call_logs", device.get("calls", [])))
        
        quick_stats = {
            "total_files": 1,
            "total_contacts": len(contacts_list) if isinstance(contacts_list, list) else 0,
            "total_messages": len(messages_list) if isinstance(messages_list, list) else 0,
            "total_calls": len(calls_list) if isinstance(calls_list, list) else 0,
            "tampered_files": 1 if data.get("tampered", False) else 0,
            "clean_files": 0 if data.get("tampered", False) else 1
        }
        
        logger.info(f"Quick stats calculated: contacts={quick_stats['total_contacts']}, messages={quick_stats['total_messages']}, calls={quick_stats['total_calls']}")
        
        # Add ZIP info to stats if it's a ZIP file
        if zip_info.get('is_zip'):
            quick_stats['is_zip'] = True
            quick_stats['images_count'] = len(zip_info.get('images', []))
            quick_stats['videos_count'] = len(zip_info.get('videos', []))
            quick_stats['json_files_count'] = len(zip_info.get('json_files', []))

        # Use encrypted filename in response if file was encrypted
        response_filename = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename

        response_data = {
            "status": "SUCCESS",
            "message": "File uploaded successfully and set as active.",
            "filename": response_filename,
            "active": True,
            "quick_stats": quick_stats,
            "validation": {
                "is_valid": True,
                "message": validation_result['message']
            }
        }
        
        if warnings:
            response_data["warnings"] = warnings
        
        # Verify data is accessible before returning
        try:
            verify_data = get_current_data()
            if not verify_data or active_filename not in verify_data:
                logger.warning(f"Data verification failed: filename {active_filename} not in ACTIVE_DATA")
            else:
                logger.info(f"Data verification successful: filename {active_filename} found in ACTIVE_DATA with {len(verify_data[active_filename].get('contacts', []))} contacts, {len(verify_data[active_filename].get('messages', []))} messages")
        except Exception as e:
            logger.error(f"Error verifying data: {e}", exc_info=True)
        
        # Reset semantic extractor's data index cache when new file is uploaded
        global semantic_extractor
        if semantic_extractor:
            semantic_extractor._data_index = {}  # Clear cached data index to force rebuild
            logger.info("✅ Cleared semantic extractor data index cache for new upload")
        
        # Rebuild RAG index after successful upload
        try:
            rebuild_rag_index()
            logger.info("✅ RAG index rebuilt successfully with new data")
        except Exception as e:
            logger.warning(f"Error rebuilding RAG index: {e}", exc_info=True)
        
        # Clean up temporary decrypted file if it was created
        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
            try:
                os.remove(temp_decrypted_file)
                logger.info(f"✅ Cleaned up temporary decrypted file: {temp_decrypted_file}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp decrypted file {temp_decrypted_file}: {e}")
        
        return jsonify(response_data)
    
    except Exception as e:
        # Catch any unhandled exceptions
        logger.error(f"Error in upload_file: {str(e)}", exc_info=True)
        # Try to remove file if it was saved
        try:
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            # Also clean up temp decrypted file if it exists
            if 'temp_decrypted_file' in locals() and temp_decrypted_file and os.path.exists(temp_decrypted_file):
                os.remove(temp_decrypted_file)
                logger.info(f"✅ Cleaned up temp decrypted file on error: {temp_decrypted_file}")
        except:
            pass
        
        # Provide user-friendly error message
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return jsonify({
                "status": "ERROR",
                "message": "Upload timeout. The file might be too large or the server is busy. Please try again."
            }), 500
        elif "memory" in error_msg.lower() or "MemoryError" in error_msg:
            return jsonify({
                "status": "ERROR",
                "message": "File is too large to process. Please reduce the file size or split it into smaller files."
            }), 500
        else:
            return jsonify({
                "status": "ERROR",
                "message": f"Error processing file: {error_msg}. Please check the file format and try again."
            }), 500

@app.route('/api/uploaded-files')
def get_uploaded_files():
    """Get list of uploaded files (JSON and ZIP) for current session."""
    try:
        uploaded_files = []
        
        # If we have a session_id, get files from session_files table
        if SESSION_DB_AVAILABLE:
            session_id = session.get('session_id') or request.args.get('session_id')
            logger.info(f"📋 Getting uploaded files for session_id: {session_id}")
            
            if session_id and session_id != 'None' and session_id != '':
                session_files = get_session_files(session_id)
                logger.info(f"📁 Found {len(session_files)} file(s) in database for session {session_id}")
                
                for file_record in session_files:
                    filename = file_record['filename']
                    file_path_recorded = file_record.get('file_path', filename)
                    # Use recorded path or fallback to UPLOAD_FOLDER
                    if os.path.isabs(file_path_recorded) and os.path.exists(file_path_recorded):
                        file_path = file_path_recorded
                    else:
                        file_path = os.path.join(UPLOAD_FOLDER, filename)
                    
                    # Check if file exists (try both encrypted and unencrypted versions)
                    if not os.path.exists(file_path):
                        # Try encrypted version
                        encrypted_path = file_path + '.encrypted'
                        if os.path.exists(encrypted_path):
                            file_path = encrypted_path
                        else:
                            logger.warning(f"   ⚠️ File not found: {filename} at {file_path} or {encrypted_path}")
                            continue
                    
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        # Determine file type (check original filename, not encrypted path)
                        base_filename = filename.replace('.encrypted', '')
                        file_type = 'ZIP' if base_filename.endswith('.zip') else 'JSON'
                        # Check if it's encrypted
                        is_encrypted = file_path.endswith('.encrypted')
                        uploaded_files.append({
                            "filename": filename,  # Keep original filename from database
                            "size": file_size,
                            "size_mb": round(file_size / (1024 * 1024), 2),
                            "type": file_type,
                            "encrypted": is_encrypted,
                            "active": filename == ACTIVE_FILENAME or filename.replace('.encrypted', '') == ACTIVE_FILENAME
                        })
                        logger.info(f"   ✅ Added file: {filename} {'(encrypted)' if is_encrypted else ''}")
                    else:
                        logger.warning(f"   ⚠️ File not found: {filename} at {file_path}")
                
                return jsonify({
                    "uploaded_files": uploaded_files,
                    "count": len(uploaded_files),
                    "session_id": session_id
                })
            else:
                logger.warning(f"⚠️ No valid session_id provided")
        
        # Fallback: get all files from UPLOAD_FOLDER (for backward compatibility)
        logger.info(f"📂 Falling back to UPLOAD_FOLDER listing")
        if os.path.exists(UPLOAD_FOLDER):
            for file in os.listdir(UPLOAD_FOLDER):
                if file.endswith('.json') or file.endswith('.zip'):
                    file_path = os.path.join(UPLOAD_FOLDER, file)
                    file_size = os.path.getsize(file_path)
                    file_type = 'ZIP' if file.endswith('.zip') else 'JSON'
                    uploaded_files.append({
                        "filename": file,
                        "size": file_size,
                        "size_mb": round(file_size / (1024 * 1024), 2),
                        "type": file_type,
                        "active": file == ACTIVE_FILENAME
                    })
        
        return jsonify({
            "uploaded_files": uploaded_files,
            "count": len(uploaded_files)
        })
    except Exception as e:
        logger.error(f"❌ Error getting uploaded files: {e}", exc_info=True)
        return jsonify({"error": str(e)})

@app.route('/api/clear-uploads', methods=['POST'])
def clear_uploads():
    """Clear all uploaded files (including encrypted versions)."""
    try:
        files_removed = []
        if os.path.exists(UPLOAD_FOLDER):
            for file in os.listdir(UPLOAD_FOLDER):
                file_path = os.path.join(UPLOAD_FOLDER, file)
                # Remove all files except .encrypted files (we'll handle those separately)
                if file.endswith('.json') or file.endswith('.zip'):
                    # Skip if this is an encrypted file (we'll remove it when we find the original)
                    if not file.endswith('.encrypted'):
                        try:
                            os.remove(file_path)
                            files_removed.append(file)
                        except Exception as e:
                            logger.warning(f"Failed to remove {file}: {e}")
                # Also remove encrypted files
                elif file.endswith('.encrypted'):
                    try:
                        os.remove(file_path)
                        files_removed.append(file)
                    except Exception as e:
                        logger.warning(f"Failed to remove {file}: {e}")
        
        # Clear active context; require upload before answering
        global ACTIVE_FILENAME, ACTIVE_DATA
        ACTIVE_FILENAME = None
        ACTIVE_DATA = {}
        nl_engine.update_data(ACTIVE_DATA)
        
        # Rebuild RAG index after clearing
        try:
            rebuild_rag_index()
        except Exception:
            pass
        return jsonify({
            "status": "SUCCESS",
            "message": "All uploaded files cleared. Using only synthetic data."
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"Error clearing files: {str(e)}"})

@app.route('/api/remove-upload/<filename>', methods=['DELETE'])
def remove_upload(filename):
    """Remove a specific uploaded file (both encrypted and decrypted versions)."""
    try:
        # Secure the filename
        secure_name = secure_filename(filename)
        file_path = os.path.join(UPLOAD_FOLDER, secure_name)
        
        files_removed = []
        
        # Check if file exists (could be encrypted or unencrypted)
        if os.path.exists(file_path):
            os.remove(file_path)
            files_removed.append(secure_name)
            logger.info(f"Removed file: {secure_name}")
        
        # Also check for encrypted version
        encrypted_file_path = file_path + '.encrypted'
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            files_removed.append(secure_name + '.encrypted')
            logger.info(f"Removed encrypted file: {secure_name}.encrypted")
        
        # Also check if the file being deleted IS an encrypted file, remove decrypted version too
        if secure_name.endswith('.encrypted'):
            decrypted_file_path = file_path.replace('.encrypted', '')
            if os.path.exists(decrypted_file_path):
                os.remove(decrypted_file_path)
                files_removed.append(secure_name.replace('.encrypted', ''))
                logger.info(f"Removed decrypted file: {secure_name.replace('.encrypted', '')}")
        
        if not files_removed:
            return jsonify({
                "status": "ERROR",
                "message": f"File {filename} not found."
            })
        
        # Remove from session_files table if we have a session_id
        if SESSION_DB_AVAILABLE:
            session_id = session.get('session_id')
            if session_id and session_id != 'None' and session_id != '':
                # Remove both encrypted and unencrypted versions from database
                delete_session_file(session_id, secure_name)
                if secure_name.endswith('.encrypted'):
                    delete_session_file(session_id, secure_name.replace('.encrypted', ''))
                else:
                    delete_session_file(session_id, secure_name + '.encrypted')
                logger.info(f"Removed file {secure_name} from session {session_id}")
        
        # If the removed file was active, clear active context
        global ACTIVE_FILENAME, ACTIVE_DATA
        base_name = secure_name.replace('.encrypted', '')
        if base_name == (ACTIVE_FILENAME or "").replace('.encrypted', ''):
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            nl_engine.update_data(ACTIVE_DATA)
        
        return jsonify({
            "status": "SUCCESS",
            "message": f"File {filename} removed successfully. ({len(files_removed)} file(s) deleted)",
            "files_removed": files_removed
        })
    except Exception as e:
        logger.error(f"Error removing file: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": f"Error removing file: {str(e)}"})

@app.route('/api/stats')
def get_stats():
    """Get basic statistics about the loaded data."""
    try:
        data_src = get_current_data()
        # Compute AI summary strictly from ACTIVE_DATA if analyzer exists
        ai_summary_out = {"analysis_available": False}
        try:
            if data_src and hasattr(engine, 'ai_analyzer') and engine.ai_analyzer:
                ai_summary = engine.ai_analyzer.analyze_multiple_files(data_src)
                ai_summary_out = {
                    "analysis_available": True,
                    "total_files_analyzed": len(data_src),
                    "risk_distribution": ai_summary.get("comparative_analysis", {}).get("risk_distribution", {}),
                    "average_risk_score": ai_summary.get("comparative_analysis", {}).get("average_risk_score", 0),
                    "overall_assessment": ai_summary.get("summary", {}).get("overall_assessment", "")
                }
        except Exception:
            ai_summary_out = {"analysis_available": False}

        # Calculate stats with proper nested structure handling
        total_contacts = 0
        total_messages = 0
        total_calls = 0
        total_device_files = 0
        total_images = 0
        total_videos = 0
        is_zip_file = False
        
        # Check for ZIP info (images/videos from ZIP files)
        if '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                is_zip_file = True
                total_images = len(zip_info.get('images', []))
                total_videos = len(zip_info.get('videos', []))
        
        # Log data source info for debugging
        logger.info(f"Stats calculation: data_src has {len(data_src)} items, keys: {list(data_src.keys())}")
        
        # Also check in file data (if ZIP info is nested in file data)
        for filename, file_data in data_src.items():
            if filename == '_zip_info':
                continue  # Skip ZIP info metadata
                
            if isinstance(file_data, dict):
                # Check for ZIP info in file data
                if '_zip_info' in file_data:
                    zip_info = file_data.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        is_zip_file = True
                        total_images = len(zip_info.get('images', []))
                        total_videos = len(zip_info.get('videos', []))
                
                # Handle nested structure with devices array (V2 format)
                devices = file_data.get("devices", [])
                if devices and isinstance(devices, list) and len(devices) > 0:
                    # V2 format: data is in devices array
                    for device in devices:
                        if isinstance(device, dict):
                            total_contacts += len(device.get("contacts", []))
                            total_messages += len(device.get("messages", []))
                            total_calls += len(device.get("call_logs", device.get("calls", [])))
                            total_device_files += len(device.get("files", []))
                else:
                    # V1 format: flat structure (contacts, messages, call_logs at top level)
                    # This is the format returned by normalize_zip_to_ufdr() and normalize_ufdr_data()
                    file_contacts = file_data.get("contacts", [])
                    file_messages = file_data.get("messages", [])
                    file_calls = file_data.get("call_logs", file_data.get("calls", []))
                    
                    # Ensure we're working with lists
                    if isinstance(file_contacts, list):
                        total_contacts += len(file_contacts)
                    if isinstance(file_messages, list):
                        total_messages += len(file_messages)
                    if isinstance(file_calls, list):
                        total_calls += len(file_calls)
                    total_device_files += len(file_data.get("files", []))
                    
                    # Log for debugging
                    logger.info(f"Stats for {filename}: contacts={len(file_contacts) if isinstance(file_contacts, list) else 0}, messages={len(file_messages) if isinstance(file_messages, list) else 0}, calls={len(file_calls) if isinstance(file_calls, list) else 0}")
                    logger.debug(f"File data keys for {filename}: {list(file_data.keys())[:10]}")  # Log first 10 keys

        # Count actual files (exclude _zip_info which is metadata)
        actual_files = {k: v for k, v in data_src.items() if k != '_zip_info'}
        
        stats = {
            "total_files": len(actual_files),
            "tampered_files": sum(1 for data in actual_files.values() if isinstance(data, dict) and data.get("tampered", False)),
            "clean_files": sum(1 for data in actual_files.values() if isinstance(data, dict) and not data.get("tampered", False)),
            "total_contacts": total_contacts,
            "total_messages": total_messages,
            "total_calls": total_calls,
            "total_device_files": total_device_files,
            "total_images": total_images,
            "total_videos": total_videos,
            "is_zip": is_zip_file,
            "uploaded_files_count": len([f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.json')]) if os.path.exists(UPLOAD_FOLDER) else 0,
            "ai_analysis": ai_summary_out
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/images')
def get_images():
    """Get list of images from ZIP files."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({"images": [], "count": 0})
        
        images_list = []
        seen_paths = set()  # Track seen paths to avoid duplicates
        
        # Check for ZIP info at top level
        if '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                for img_info in zip_info.get('images', []):
                    rel_path = img_info.get('rel_path', '')
                    if rel_path and rel_path not in seen_paths:
                        seen_paths.add(rel_path)
                        images_list.append({
                            'name': img_info.get('name', 'unknown'),
                            'path': rel_path,
                            'full_path': img_info.get('path', '')
                        })
        
        # Also check in file data
        for filename, file_data in data_src.items():
            if filename == '_zip_info':
                continue
            if isinstance(file_data, dict) and '_zip_info' in file_data:
                zip_info = file_data.get('_zip_info', {})
                if zip_info.get('is_zip'):
                    for img_info in zip_info.get('images', []):
                        rel_path = img_info.get('rel_path', '')
                        if rel_path and rel_path not in seen_paths:
                            seen_paths.add(rel_path)
                            images_list.append({
                                'name': img_info.get('name', 'unknown'),
                                'path': rel_path,
                                'full_path': img_info.get('path', '')
                            })
        
        return jsonify({
            "images": images_list,
            "count": len(images_list)
        })
    except Exception as e:
        logger.error(f"Error getting images: {e}")
        return jsonify({"images": [], "count": 0, "error": str(e)})

@app.route('/api/detect-images', methods=['POST'])
@login_required
def detect_images():
    """Process all images in the gallery using EBI-scan face and object detection."""
    try:
        import sys
        
        # Add EBI-scan backend to path
        ebi_scan_path = os.path.join(EVI_SCAN_DIR, 'Image Model', 'EBI-scan-main', 'backend')
        if ebi_scan_path not in sys.path:
            sys.path.insert(0, ebi_scan_path)
        
        # Import EBI-scan services
        try:
            from app.services.face_detection import face_detection_service
            from app.services.object_detection import object_detection_service
            from app.services.image_processor import validate_image
        except ImportError as import_err:
            logger.error(f"EBI-scan import error: {import_err}")
            return jsonify({
                "error": "EBI-scan services not available. Please ensure EBI-scan dependencies are installed.",
                "processed": 0,
                "results": []
            }), 500
        
        # Get current images
        data_src = get_current_data()
        if not data_src:
            return jsonify({"error": "No data source available", "processed": 0, "results": []})
        
        images_list = []
        seen_paths = set()
        
        # Collect all images (same logic as /api/images)
        if '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                for img_info in zip_info.get('images', []):
                    rel_path = img_info.get('rel_path', '')
                    if rel_path and rel_path not in seen_paths:
                        seen_paths.add(rel_path)
                        images_list.append({
                            'name': img_info.get('name', 'unknown'),
                            'path': rel_path,
                            'full_path': img_info.get('path', '')
                        })
        
        for filename, file_data in data_src.items():
            if filename == '_zip_info':
                continue
            if isinstance(file_data, dict) and '_zip_info' in file_data:
                zip_info = file_data.get('_zip_info', {})
                if zip_info.get('is_zip'):
                    for img_info in zip_info.get('images', []):
                        rel_path = img_info.get('rel_path', '')
                        if rel_path and rel_path not in seen_paths:
                            seen_paths.add(rel_path)
                            images_list.append({
                                'name': img_info.get('name', 'unknown'),
                                'path': rel_path,
                                'full_path': img_info.get('path', '')
                            })
        
        if not images_list:
            return jsonify({"error": "No images found", "processed": 0, "results": []})
        
        # Process images
        results = []
        processed = 0
        errors = []
        
        for img_info in images_list:
            try:
                full_path = img_info.get('full_path', '')
                if not full_path or not os.path.exists(full_path):
                    errors.append(f"{img_info['name']}: File not found")
                    continue
                
                # Validate image
                is_valid, error_msg = validate_image(full_path)
                if not is_valid:
                    errors.append(f"{img_info['name']}: {error_msg}")
                    continue
                
                # Detect faces
                faces = face_detection_service.detect_faces(full_path)
                
                # Detect objects
                objects = object_detection_service.detect_objects(full_path)
                
                results.append({
                    'image_name': img_info['name'],
                    'image_path': img_info['path'],
                    'faces_detected': len(faces),
                    'faces': [
                        {
                            'location': face['face_location'],
                            'confidence': face.get('confidence', 0.0)
                        }
                        for face in faces
                    ],
                    'objects_detected': len(objects),
                    'objects': [
                        {
                            'type': obj['object_type'],
                            'location': obj['object_location'],
                            'confidence': obj.get('confidence', 0.0)
                        }
                        for obj in objects
                    ]
                })
                processed += 1
                logger.info(f"Processed {img_info['name']}: {len(faces)} faces, {len(objects)} objects")
                
            except Exception as e:
                logger.error(f"Error processing {img_info.get('name', 'unknown')}: {e}", exc_info=True)
                errors.append(f"{img_info.get('name', 'unknown')}: {str(e)}")
        
        return jsonify({
            "success": True,
            "processed": processed,
            "total": len(images_list),
            "results": results,
            "errors": errors[:10]  # Limit error details
        })
        
    except Exception as e:
        logger.error(f"Error in detect_images: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "processed": 0,
            "results": []
        }), 500

@app.route('/api/ai-analysis')
def get_ai_analysis():
    """Get AI analysis results."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"status": "ERROR", "message": "Upload a UFDR JSON file first."})
        if not hasattr(engine, 'ai_analyzer') or not engine.ai_analyzer:
            return jsonify({"status": "ERROR", "message": "AI analyzer unavailable in this build."})
        analysis_result = engine.ai_analyzer.analyze_multiple_files(ACTIVE_DATA)
        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis_result
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/ai-analysis/<filename>')
def get_file_ai_analysis(filename):
    """Get AI analysis for a specific file."""
    try:
        if not hasattr(engine, 'ai_analyzer') or not engine.ai_analyzer:
            return jsonify({"status": "ERROR", "message": "AI analyzer unavailable in this build."})
        if ACTIVE_DATA and filename in ACTIVE_DATA:
            analysis = engine.ai_analyzer.analyze_ufdr_file(filename, ACTIVE_DATA[filename])
            return jsonify({
                "status": "SUCCESS",
                "analysis": analysis
            })
        else:
            return jsonify({
                "status": "NOT_FOUND",
                "message": f"File '{filename}' not found"
            })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/nl-query', methods=['POST'])
def nl_query():
    """Enhanced natural language query endpoint with robust keyword detection."""
    try:
        data = request.get_json() or {}
        query = (data.get('query') or '').strip()
        use_enhanced = data.get('enhanced', True)  # Default to enhanced engine
        
        if not query:
            return jsonify({"error": "No query provided."})

        # Ensure we have data to query (fallback to synthetic if no uploads)
        data_src = get_current_data()
        if not data_src:
            return jsonify({"error": "Upload a UFDR JSON file first."})
        
        if use_enhanced:
            # Use enhanced engine for better keyword detection and analysis
            enhanced_nl_engine.update_data(data_src)
            result = enhanced_nl_engine.query(query)
            
            # Convert QueryResult to JSON-serializable format
            response = {
                "query": result.query,
                "analysis_type": result.analysis_type,
                "confidence": result.confidence,
                "keywords_found": result.keywords_found,
                "summary": result.summary,
                "total_matches": len(result.matches),
                "matches": result.matches[:50],  # Limit to first 50 matches for performance
                "recommendations": result.recommendations,
                "enhanced": True
            }
            
            # Add statistics if available
            try:
                stats = enhanced_nl_engine.get_analysis_statistics()
                response["statistics"] = stats
            except Exception:
                pass
                
            return jsonify(response)
        else:
            # Use original engine for backward compatibility
            nl_engine.update_data(data_src)
            result = nl_engine.answer(query)
            result["enhanced"] = False
            return jsonify(result)
            
    except Exception as e:
        return jsonify({"error": f"Failed to process query: {str(e)}"})

@app.route('/api/enhanced-suggestions')
def get_enhanced_suggestions():
    """Get intelligent query suggestions based on loaded data and forensic categories."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({"error": "Upload a UFDR JSON file first."})
        
        # Update enhanced engine with current data
        enhanced_nl_engine.update_data(data_src)
        
        # Get data statistics for intelligent suggestions
        stats = enhanced_nl_engine.get_analysis_statistics()
        
        # Generate context-aware suggestions
        suggestions = {
            "Financial Investigation": [
                "Find suspicious money transfers",
                "Show me financial transactions",
                "Analyze payment patterns",
                "Look for money laundering indicators",
                "Find urgent financial requests"
            ],
            "Identity & Security": [
                "Find identity theft attempts",
                "Show password sharing activities", 
                "Look for phishing attempts",
                "Find credential compromise indicators",
                "Analyze authentication patterns"
            ],
            "Data & Privacy": [
                "Find data breach indicators",
                "Show file sharing activities",
                "Look for confidential data leaks",
                "Analyze document access patterns",
                "Find unauthorized data transfers"
            ],
            "Threat Analysis": [
                "Find threat indicators",
                "Look for violent content",
                "Analyze threatening communications",
                "Find planning activities",
                "Show high-risk conversations"
            ],
            "Communication Patterns": [
                "Analyze communication frequency",
                "Find unusual contact patterns",
                "Show relationship networks",
                "Look for coordinated activities",
                "Analyze time-based patterns"
            ],
            "Timeline & Events": [
                "Show timeline of activities",
                "Find activity clusters",
                "Analyze event sequences",
                "Look for synchronized communications",
                "Show chronological patterns"
            ]
        }
        
        # Add data-specific suggestions based on available content
        data_specific = []
        if stats['total_messages'] > 0:
            data_specific.append(f"Analyze {stats['total_messages']} messages for patterns")
        if stats['total_calls'] > 0:
            data_specific.append(f"Investigate {stats['total_calls']} call records")
        if stats['total_contacts'] > 0:
            data_specific.append(f"Review {stats['total_contacts']} contacts for relationships")
        if stats['top_contacts']:
            top_contact = stats['top_contacts'][0]['contact']
            data_specific.append(f"Analyze communications with {top_contact}")
        
        if data_specific:
            suggestions["Data-Specific Analysis"] = data_specific
        
        return jsonify({
            "suggestions": suggestions,
            "statistics": stats,
            "enhanced": True
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate suggestions: {str(e)}"})

@app.route('/api/comprehensive-analysis')
def get_comprehensive_analysis():
    """Get comprehensive scenario analysis using the comprehensive query engine."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Get comprehensive analysis
        analysis = simplified_engine.get_comprehensive_scenario_analysis(records)
        
        # Get suggested queries
        suggested_queries = simplified_engine.suggest_comprehensive_queries(analysis['scenario'])
        
        return jsonify({
            "analysis": analysis,
            "suggested_queries": suggested_queries,
            "total_records_analyzed": len(records)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to perform comprehensive analysis: {str(e)}"})

@app.route('/api/simplified-query', methods=['POST'])
def simplified_query():
    """Process simplified natural language query without external dependencies."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 100)
        
        if not query:
            return jsonify({"error": "No query provided"})
        
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Process query with simplified engine
        results, explanation = simplified_engine.process_query(query, records, None, limit)
        
        # Format results for display
        formatted_results = []
        for result in results:
            formatted_result = {
                "content": result.get('text', result.get('message', '')),
                "timestamp": result.get('timestamp', ''),
                "from": result.get('from', ''),
                "to": result.get('to', ''),
                "type": result.get('type', ''),
                "relevance_score": result.get('_relevance_score', 0),
                "matched_keywords": result.get('_matched_keywords', []),
                "matched_patterns": result.get('_matched_patterns', []),
                "matched_entities": result.get('_matched_entities', [])
            }
            formatted_results.append(formatted_result)
        
        return jsonify({
            "results": formatted_results,
            "explanation": explanation,
            "total_found": len(formatted_results)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to process simplified query: {str(e)}"})

@app.route('/api/simplified-analysis')
def get_simplified_analysis():
    """Get simplified scenario analysis without external dependencies."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Get simplified analysis
        analysis = simplified_engine.get_scenario_summary(records)
        
        # Get suggested queries
        suggested_queries = simplified_engine.suggest_queries(analysis['scenario'])
        
        return jsonify({
            "analysis": analysis,
            "suggested_queries": suggested_queries,
            "total_records_analyzed": len(records)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to perform simplified analysis: {str(e)}"})

@app.route('/api/comprehensive-query', methods=['POST'])
def comprehensive_query():
    """Process comprehensive natural language query."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 100)
        
        if not query:
            return jsonify({"error": "No query provided"})
        
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Process query with comprehensive engine
        results, explanation = simplified_engine.process_query(query, records, None, limit)
        
        # Format results for display
        formatted_results = []
        for result in results:
            formatted_result = {
                "content": result.get('text', result.get('message', '')),
                "timestamp": result.get('timestamp', ''),
                "from": result.get('from', ''),
                "to": result.get('to', ''),
                "type": result.get('type', ''),
                "relevance_score": result.get('_relevance_score', 0),
                "matched_keywords": result.get('_matched_keywords', []),
                "matched_patterns": result.get('_matched_patterns', []),
                "matched_entities": result.get('_matched_entities', [])
            }
            formatted_results.append(formatted_result)
        
        return jsonify({
            "results": formatted_results,
            "explanation": explanation,
            "total_found": len(formatted_results)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to process comprehensive query: {str(e)}"})

@app.route('/api/ai-retrieval', methods=['POST'])
def ai_retrieval():
    """AI-powered intelligent data retrieval endpoint."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 50)
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided"
            })
        
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        
        # Perform AI-powered retrieval
        # Rebuild retrieval engine with current data
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        result = ai_retrieval_engine.intelligent_search(query, limit)
        
        return jsonify({
            "status": "SUCCESS",
            "query": result.query,
            "matches": result.matches,
            "confidence": result.confidence,
            "data_sources": result.data_sources,
            "semantic_mappings": result.semantic_mappings,
            "summary": result.summary,
            "recommendations": result.recommendations,
            "total_matches": len(result.matches)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error in AI retrieval: {str(e)}"
        })

@app.route('/api/owner-info')
def get_owner_info():
    """Get all device owner information from loaded UFDR data."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        owners = ai_retrieval_engine.get_owner_information()
        
        return jsonify({
            "status": "SUCCESS",
            "owners": owners,
            "total_owners": len(owners)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error retrieving owner information: {str(e)}"
        })

@app.route('/api/llm-models', methods=['GET'])
def get_llm_models():
    """Get available LLM models from LM Studio."""
    try:
        if not USE_LLM:
            return jsonify({"error": "LLM integration is disabled"})
        
        response = requests.get("http://localhost:1234/v1/models", timeout=5)
        if response.ok:
            models_data = response.json()
            models = []
            for model in models_data.get('data', []):
                models.append({
                    'name': model.get('id', 'Unknown'),
                    'size': model.get('size', 'Unknown'),
                    'parameter_size': 'Unknown',
                    'family': 'Unknown'
                })
            return jsonify({
                "status": "success",
                "current_model": LLM_MODEL,
                "models": models
            })
        else:
            return jsonify({"error": "Could not connect to LM Studio"})
    except Exception as e:
        return jsonify({"error": f"Error fetching models: {str(e)}"})

@app.route('/api/llm-switch', methods=['POST'])
def switch_llm_model():
    """Switch the active LLM model."""
    global LLM_MODEL
    try:
        data = request.get_json() or {}
        new_model = data.get('model', '').strip()
        
        if not new_model:
            return jsonify({"error": "No model specified"})
        
        if new_model not in AVAILABLE_MODELS:
            return jsonify({"error": f"Model {new_model} not available"})
        
        # Test the model
        test_response = requests.post(LLM_URL, json={
            "model": new_model, 
            "prompt": "Test", 
            "stream": False
        }, timeout=10)
        
        if test_response.ok:
            LLM_MODEL = new_model
            return jsonify({
                "status": "success",
                "message": f"Switched to {new_model}",
                "current_model": LLM_MODEL
            })
        else:
            return jsonify({"error": f"Model {new_model} is not responding"})
            
    except Exception as e:
        return jsonify({"error": f"Error switching model: {str(e)}"})

@app.route('/api/device-metadata', methods=['POST'])
def search_device_metadata():
    """Search specifically in device metadata for owner and registration information."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided"
            })
        
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        results = ai_retrieval_engine.search_device_metadata(query)
        
        return jsonify({
            "status": "SUCCESS",
            "query": query,
            "results": results,
            "total_results": len(results)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error searching device metadata: {str(e)}"
        })

# Note: Using LM Studio directly with model name (no model name mapping needed)

@app.route('/api/models', methods=['GET'])
def get_available_models():
    """Get list of available AI models from LM Studio and local models."""
    try:
        models = []
        
        # Add Qwen2.5-VL-7B as a local model (if enabled)
        if USE_QWEN_VL:
            qwen_status = "loaded" if QWEN_VL_LOADED else "available"
            models.append({
                "id": "qwen/qwen2.5-vl-7b",
                "name": "Qwen2.5-VL-7B",
                "description": "Multimodal model for image/video analysis (Local Transformers)",
                "provider": "Local (Transformers)",
                "available": True,
                "status": qwen_status,
                "is_local": True
            })
        
        # Check what models are actually available in LM Studio
        try:
            lm_studio_response = requests.get("http://localhost:1234/v1/models", timeout=5)
            if lm_studio_response.ok:
                lm_studio_models = lm_studio_response.json().get('data', [])
                for model_data in lm_studio_models:
                    model_id = model_data.get('id', 'Unknown')

                    # Skip heavy / non-chat models in this UI (too slow or not suitable for chat)
                    # This hides them from the dropdown but does not affect LM Studio itself.
                    lower_id = model_id.lower()
                    if any(bad in lower_id for bad in ['7b', '8b', 'embed', 'embedding']):
                        continue

                    models.append({
                        "id": model_id,
                        "name": model_id,
                        "description": f"Model loaded in LM Studio",
                        "provider": "LM Studio",
                        "available": True,
                        "is_local": False
                    })
        except Exception as e:
            logger.warning(f"Could not fetch LM Studio models: {e}")
        
        # If no models found, still return SUCCESS but with empty array
        # Frontend will handle displaying appropriate message
        return jsonify({
            "status": "SUCCESS",
            "models": models,
            "current_model": LLM_MODEL if models else None,
            "available_count": len(models),
            "lm_studio_connected": len([m for m in models if not m.get('is_local', False)]) > 0
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error getting models: {str(e)}"
        })

@app.route('/api/models/<path:model_id>', methods=['POST'])
def switch_model(model_id):
    """Switch to a different AI model (LM Studio or local Qwen2.5-VL-7B)."""
    global LLM_MODEL
    try:
        # For LM Studio models (including Qwen served via LM Studio), check availability
        try:
            lm_studio_response = requests.get("http://localhost:1234/v1/models", timeout=5)
            if lm_studio_response.ok:
                lm_studio_models = lm_studio_response.json().get('data', [])
                available_model_names = [model.get('id', '') for model in lm_studio_models]
                
                if model_id not in available_model_names:
                    return jsonify({
                        "status": "ERROR",
                        "message": f"Model {model_id} is not loaded in LM Studio. Available models: {', '.join(available_model_names)}"
                    })
            else:
                return jsonify({
                    "status": "ERROR",
                    "message": "Cannot connect to LM Studio"
                })
        except Exception as e:
            return jsonify({
                "status": "ERROR",
                "message": f"Error checking model availability: {str(e)}"
            })
        
        # Update global model for LM Studio models
        LLM_MODEL = model_id
        
        return jsonify({
            "status": "SUCCESS",
            "message": f"Switched to {model_id}",
            "current_model": LLM_MODEL,
            "lm_studio_name": model_id
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error switching model: {str(e)}"
        })

@app.route('/api/lm-studio/status', methods=['GET'])
def check_lm_studio_status():
    """Check LM Studio connection status and provide diagnostic info."""
    try:
        # Check if LM Studio is accessible
        health_check = requests.get("http://localhost:1234/v1/models", timeout=5)
        if health_check.ok:
            models = health_check.json().get('data', [])
            return jsonify({
                "status": "OK",
                "lm_studio_running": True,
                "models_available": [m.get('id', 'Unknown') for m in models],
                "model_count": len(models),
                "message": f"LM Studio is running with {len(models)} model(s) available"
            })
        else:
            return jsonify({
                "status": "ERROR",
                "lm_studio_running": False,
                "message": "LM Studio server is not responding properly"
            })
    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "ERROR",
            "lm_studio_running": False,
            "message": "LM Studio server is not running. Please start LM Studio server.",
            "help": {
                "windows": "Open LM Studio application, go to 'Local Server' tab, and click 'Start Server'",
                "mac_linux": "Open LM Studio application, go to 'Local Server' tab, and click 'Start Server'",
                "check": "Check LM Studio 'Local Server' tab to verify server is running"
            }
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "lm_studio_running": False,
            "message": f"Error checking LM Studio: {str(e)}"
        })

@app.route('/api/qwen-vl/status', methods=['GET'])
def qwen_vl_status():
    """Check Qwen2.5-VL-7B model status."""
    try:
        if not USE_QWEN_VL:
            return jsonify({
                "available": False,
                "enabled": False,
                "message": "Qwen2.5-VL-7B is disabled"
            })
        
        model, processor = init_qwen_vl_model()
        
        if model is None or processor is None:
            return jsonify({
                "available": False,
                "enabled": True,
                "message": "Qwen2.5-VL-7B model not loaded. Check logs for details.",
                "model_name": QWEN_VL_MODEL_NAME
            })
        
        return jsonify({
            "available": True,
            "enabled": True,
            "loaded": QWEN_VL_LOADED,
            "model_name": QWEN_VL_MODEL_NAME,
            "message": "Qwen2.5-VL-7B is ready for multimodal analysis"
        })
    except Exception as e:
        return jsonify({
            "available": False,
            "enabled": USE_QWEN_VL,
            "error": str(e),
            "message": f"Error checking Qwen2.5-VL status: {str(e)}"
        })

@app.route('/api/chat/clear', methods=['POST'])
def clear_chat_history():
    """Clear chat history for current session and reset data caches."""
    try:
        if 'session_id' in session:
            session_id = session['session_id']
            if session_id in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id] = []
            # Also clear from database
            if SESSION_DB_AVAILABLE:
                clear_chat_history(session_id)
        
        # Reset semantic extractor's data index cache to prevent old data references
        global semantic_extractor
        if semantic_extractor:
            semantic_extractor._data_index = {}  # Clear cached data index
            logger.info("✅ Cleared semantic extractor data index cache")
        
        # Rebuild RAG index with current ACTIVE_DATA (in case data changed)
        try:
            rebuild_rag_index()
            logger.info("✅ Rebuilt RAG index after chat clear")
        except Exception as e:
            logger.warning(f"Error rebuilding RAG index after chat clear: {e}")
        
        return jsonify({"status": "SUCCESS", "message": "Chat history cleared and data caches reset"})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

# Session Management API Endpoints
@app.route('/api/sessions', methods=['GET'])
@login_required
def list_sessions():
    """List all sessions for the current user, optionally filtered by case_id"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get current user ID for security
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        case_id = request.args.get('case_id', None)
        if case_id:
            # Get sessions for this case, filtered by user_id
            sessions = get_sessions_by_case(case_id, user_id=user_id)
        else:
            # Get all sessions for this user
            sessions = get_all_sessions(user_id=user_id)
        
        return jsonify({
            "status": "SUCCESS",
            "sessions": sessions,
            "count": len(sessions)
        })
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions', methods=['POST'])
@login_required
def create_new_session():
    """Create a new session"""
    try:
        data = request.get_json() or {}
        case_id = data.get('case_id')
        title = data.get('title', 'New Investigation')
        
        # Get current user ID
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Create in database with user_id
        if SESSION_DB_AVAILABLE:
            success, error_msg = create_session(session_id, case_id=case_id, title=title, user_id=user_id)
            if not success:
                error_message = error_msg or "Failed to create session in database"
                logger.error(f"Failed to create session: {error_message}")
                return jsonify({"status": "ERROR", "message": error_message}), 500
        
        # Store in Flask session
        session['session_id'] = session_id
        if case_id:
            session['case_id'] = case_id
        
        return jsonify({
            "status": "SUCCESS",
            "session_id": session_id,
            "case_id": case_id,
            "title": title,
            "message": "Session created successfully"
        })
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>', methods=['GET'])
@login_required
def get_session_info(session_id):
    """Get session information and restore state"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({
                "status": "ERROR",
                "message": "Session database not available"
            })
        
        # Get current user ID for security
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                "status": "ERROR",
                "message": "User not authenticated"
            }), 401
        
        # Get session info (filtered by user_id for security)
        sess = get_session(session_id, user_id=user_id)
        if not sess:
            return jsonify({
                "status": "ERROR",
                "message": "Session not found or access denied"
            }), 404
        
        # Get chat history
        chat_history = get_chat_history(session_id)
        logger.info(f"📜 Retrieved {len(chat_history)} chat message(s) for session {session_id}")
        
        # Get preferences
        preferences = get_preferences(session_id)
        logger.info(f"⚙️ Retrieved preferences for session {session_id}: {preferences}")
        if 'sound_enabled' in preferences:
            logger.info(f"🔊 sound_enabled value: {preferences['sound_enabled']} (type: {type(preferences['sound_enabled']).__name__})")
        
        # Get query history (last 50)
        query_history = get_query_history(session_id, limit=50)
        
        # Update last accessed
        update_session_access(session_id)
        
        # Store in Flask session
        session['session_id'] = session_id
        if sess.get('case_id'):
            session['case_id'] = sess['case_id']
        
        return jsonify({
            "status": "SUCCESS",
            "session": sess,
            "chat_history": chat_history,
            "preferences": preferences,
            "query_history": query_history
        })
    except Exception as e:
        logger.error(f"Error getting session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>/preferences', methods=['POST'])
def update_session_preferences(session_id):
    """Update session preferences"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        data = request.get_json() or {}
        logger.info(f"💾 Saving preferences for session {session_id}: {list(data.keys())}")
        logger.info(f"📥 Received data: {data}")
        
        # Update each preference
        for key, value in data.items():
            original_value = value
            save_result = save_preference(session_id, key, value)
            if save_result:
                logger.info(f"   ✅ Saved {key} = {original_value} (original) -> converted in save_preference()")
            else:
                logger.error(f"   ❌ Failed to save {key} = {original_value}")
        
        updated_prefs = get_preferences(session_id)
        logger.info(f"📋 Updated preferences after save: {updated_prefs}")
        if 'sound_enabled' in updated_prefs:
            logger.info(f"🔊 sound_enabled in response: {updated_prefs['sound_enabled']} (type: {type(updated_prefs['sound_enabled']).__name__})")
        
        return jsonify({
            "status": "SUCCESS",
            "message": "Preferences updated",
            "preferences": updated_prefs
        })
    except Exception as e:
        logger.error(f"Error updating preferences: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>/preferences', methods=['GET'])
def get_session_preferences(session_id):
    """Get session preferences"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        prefs = get_preferences(session_id)
        return jsonify({
            "status": "SUCCESS",
            "preferences": prefs
        })
    except Exception as e:
        logger.error(f"Error getting preferences: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

# Case Management API Endpoints
@app.route('/api/cases', methods=['GET'])
@login_required
def list_cases():
    """List all cases for the current user, optionally filtered by status"""
    try:
        if not SESSION_DB_AVAILABLE:
            logger.error("Session database not available for listing cases")
            return jsonify({"status": "ERROR", "message": "Session database not available"}), 500
        
        # Get current user's username to filter cases
        username = session.get('username')
        status_filter = request.args.get('status', None)
        
        # Filter cases by created_by (username) to show only user's cases
        cases = get_all_cases(status_filter=status_filter, created_by=username)
        
        logger.info(f"Retrieved {len(cases)} cases for user {username} (filter: {status_filter or 'all'})")
        
        return jsonify({
            "status": "SUCCESS",
            "cases": cases,
            "count": len(cases)
        })
    except Exception as e:
        logger.error(f"Error listing cases: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/cases', methods=['POST'])
@login_required
def create_new_case():
    """Create a new case"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # RBAC: Check permission
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            if not RBAC.has_permission('create_case', user_id):
                if audit_logger:
                    audit_logger.log_action('create_case_denied', success=False, 
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
        
        data = request.get_json() or {}
        case_name = data.get('case_name', '').strip()
        evidence_device = data.get('evidence_device', '').strip()  # Optional, can be added later
        description = data.get('description', '').strip()
        status = data.get('status', 'Active')
        
        # Get investigator from logged-in user's profile (name or username)
        investigator = session.get('name') or session.get('username') or 'Unknown Investigator'
        
        # Sanitize inputs
        if SECURITY_AVAILABLE:
            case_name = sanitize_input(case_name, max_length=200)
            investigator = sanitize_input(investigator, max_length=100)
            evidence_device = sanitize_input(evidence_device, max_length=100)
            description = sanitize_input(description, max_length=5000)
        
        if not case_name:
            return jsonify({"status": "ERROR", "message": "Case name is required"})
        
        # Generate case ID
        import uuid
        case_id = data.get('case_id') or f"C-{datetime.now().strftime('%Y')}-{str(uuid.uuid4())[:3].upper()}"
        
        # Store investigator in metadata or description
        metadata = {'investigator': investigator}
        if description:
            description = f"Investigator: {investigator}\n\n{description}"
        else:
            description = f"Investigator: {investigator}"
        
        # Get current user info
        created_by = session.get('username', 'system')
        
        # Create case
        if create_case(case_id, case_name, evidence_device=evidence_device, created_by=created_by, description=description, status=status, metadata=metadata):
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('create_case', resource=case_id, success=True,
                                      details={'case_name': case_name, 'investigator': investigator})
            
            # Get the freshly created case to ensure we have the correct timestamps
            case = get_case(case_id)
            if case:
                return jsonify({
                    "status": "SUCCESS",
                    "case": case,
                    "message": "Case created successfully"
                })
            else:
                return jsonify({"status": "ERROR", "message": "Case created but could not retrieve it"})
        else:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('create_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to create case"})
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('create_case', success=False, details={'error': str(e)})
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['GET'])
@login_required
def get_case_info(case_id):
    """Get case information"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get case first to check ownership
        case = get_case(case_id)
        if not case:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('view_case', resource=case_id, success=False,
                                      details={'error': 'case_not_found'})
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # Verify case belongs to current user (unless admin)
        username = session.get('username')
        user_role = 'viewer'
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
        
        case_owner = case.get('created_by', 'unknown')
        is_admin_access = (user_role == 'admin' and case_owner != username)
        
        # Check permissions: admin can view all, others can only view their own
        if user_role != 'admin' and case_owner != username:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('view_case_denied', resource=case_id, success=False,
                                      details={'reason': 'not_owner', 'case_owner': case_owner})
            return jsonify({"status": "ERROR", "message": "Access denied: Case does not belong to you"}), 403
        
        # Audit logging - indicate if admin accessed someone else's case
        if SECURITY_AVAILABLE and audit_logger:
            log_details = {}
            if is_admin_access:
                log_details['admin_access'] = True
                log_details['case_owner'] = case_owner
                log_details['access_type'] = 'admin_viewing_other_case'
            else:
                log_details['access_type'] = 'owner_viewing_own_case'
            
            audit_logger.log_action('view_case', resource=case_id, success=True, details=log_details)
        
        # Get the most recent session's last_accessed time for this case (for last_opened)
        if SESSION_DB_AVAILABLE:
            # Import get_db_connection from session_db
            import sys
            import os
            _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
            if _database_code_path not in sys.path:
                sys.path.insert(0, _database_code_path)
            from session_db import get_db_connection
            conn = get_db_connection()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT last_accessed 
                        FROM sessions 
                        WHERE case_id = ? 
                        ORDER BY last_accessed DESC 
                        LIMIT 1
                    """, (case_id,))
                    session_row = cur.fetchone()
                    if session_row:
                        case['last_opened'] = session_row['last_accessed']
                    else:
                        case['last_opened'] = None
                    cur.close()
                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting last_opened for case: {e}")
                    case['last_opened'] = None
        
        # Get current user ID for security
        user_id = session.get('user_id')
        
        # Get sessions for this case, filtered by user_id
        sessions = get_sessions_by_case(case_id, user_id=user_id) if user_id else get_sessions_by_case(case_id)
        
        return jsonify({
            "status": "SUCCESS",
            "case": case,
            "sessions": sessions,
            "session_count": len(sessions)
        })
    except Exception as e:
        logger.error(f"Error getting case: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['PUT'])
@login_required
def update_case_info(case_id):
    """Update case information"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get case first to check ownership
        case = get_case(case_id)
        if not case:
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # RBAC: Check permission and case ownership
        username = session.get('username')
        user_role = 'viewer'
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
            
            has_edit_permission = RBAC.has_permission('edit_case', user_id)
            has_edit_own_permission = RBAC.has_permission('edit_own_case', user_id)
            
            if not has_edit_permission and not has_edit_own_permission:
                if audit_logger:
                    audit_logger.log_action('update_case_denied', resource=case_id, success=False,
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
            
            # If user has edit_own_case but not edit_case, check ownership
            case_owner = case.get('created_by', 'unknown')
            if has_edit_own_permission and not has_edit_permission:
                if user_role != 'admin' and case_owner != username:
                    if audit_logger:
                        audit_logger.log_action('update_case_denied', resource=case_id, success=False,
                                              details={'reason': 'not_owner', 'case_owner': case_owner})
                    return jsonify({"status": "ERROR", "message": "Access denied: You don't have permission to edit this case"}), 403
        
        data = request.get_json() or {}
        updates = {}
        
        if 'case_name' in data:
            updates['case_name'] = sanitize_input(data['case_name'], max_length=200) if SECURITY_AVAILABLE else data['case_name']
        if 'status' in data:
            updates['status'] = data['status']
        if 'evidence_device' in data:
            updates['evidence_device'] = sanitize_input(data['evidence_device'], max_length=100) if SECURITY_AVAILABLE else data['evidence_device']
        if 'description' in data:
            updates['description'] = sanitize_input(data['description'], max_length=5000) if SECURITY_AVAILABLE else data['description']
        
        if update_case(case_id, **updates):
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('update_case', resource=case_id, success=True,
                                      details={'updated_fields': list(updates.keys())})
            
            case = get_case(case_id)
            return jsonify({
                "status": "SUCCESS",
                "case": case,
                "message": "Case updated successfully"
            })
        else:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('update_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to update case"})
    except Exception as e:
        logger.error(f"Error updating case: {e}")
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('update_case', resource=case_id, success=False, details={'error': str(e)})
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['DELETE'])
@login_required
def delete_case_info(case_id):
    """Delete a case"""
    try:
        if not SESSION_DB_AVAILABLE:
            logger.error("Session database not available for delete operation")
            return jsonify({"status": "ERROR", "message": "Session database not available"}), 500
        
        # RBAC: Check permission (allow delete_case or edit_own_case for investigators)
        if SECURITY_AVAILABLE:
            has_delete_permission = RBAC.has_permission('delete_case')
            has_edit_own_permission = RBAC.has_permission('edit_own_case')
            
            if not has_delete_permission and not has_edit_own_permission:
                if audit_logger:
                    audit_logger.log_action('delete_case_denied', resource=case_id, success=False,
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
            
            # If user has edit_own_case but not delete_case, check case ownership
            if has_edit_own_permission and not has_delete_permission:
                # Get case to check ownership
                case = get_case(case_id)
                if case:
                    username = session.get('username')
                    user_id = session.get('user_id')
                    user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
                    case_owner = case.get('created_by', 'unknown')
                    if user_role != 'admin' and case_owner != username:
                        if audit_logger:
                            audit_logger.log_action('delete_case_denied', resource=case_id, success=False,
                                                  details={'reason': 'not_owner', 'case_owner': case_owner})
                        return jsonify({"status": "ERROR", "message": "Access denied: You don't have permission to delete this case"}), 403
        
        # Verify case exists before deleting
        case = get_case(case_id)
        if not case:
            logger.warning(f"Attempted to delete non-existent case: {case_id}")
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=False,
                                      details={'error': 'case_not_found'})
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # Delete the case
        if delete_case(case_id):
            logger.info(f"Case {case_id} deleted successfully")
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=True,
                                      details={'case_name': case.get('case_name', 'Unknown')})
            return jsonify({
                "status": "SUCCESS",
                "message": "Case deleted successfully"
            })
        else:
            logger.error(f"Failed to delete case {case_id}")
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to delete case"}), 500
    except Exception as e:
        logger.error(f"Error deleting case {case_id}: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/cases/<case_id>/create-session', methods=['POST'])
def create_case_session(case_id):
    """Create a new EVI SCAN session for a case"""
    # Declare global variables at the top of the function
    global ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine
    
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Verify case exists
        case = get_case(case_id)
        if not case:
            return jsonify({"status": "ERROR", "message": "Case not found"})
        
        # Get request data to check if this is a new session (not continuing existing)
        data = request.get_json() or {}
        is_new_session = data.get('is_new_session', True)  # Default to True for new sessions
        
        # Check if this is a brand new case (no previous sessions) or restoring existing
        existing_sessions = []
        if SESSION_DB_AVAILABLE:
            existing_sessions = get_sessions_by_case(case_id)
        
        is_brand_new_case = len(existing_sessions) == 0
        
        # If creating a NEW CASE (no previous sessions), clear everything including files
        if is_new_session and is_brand_new_case:
            logger.info(f"Creating NEW CASE {case_id} (no previous sessions) - clearing ALL files and ACTIVE_DATA")
            
            # Clear all uploaded files from disk for brand new cases
            if os.path.exists(UPLOAD_FOLDER):
                for file in os.listdir(UPLOAD_FOLDER):
                    file_path = os.path.join(UPLOAD_FOLDER, file)
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            logger.info(f"Removed uploaded file: {file}")
                    except Exception as e:
                        logger.warning(f"Error removing file {file}: {e}")
            
            # Clear ACTIVE_DATA and reset engines
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            
            # Reset engines with empty data
            try:
                nl_engine.update_data(ACTIVE_DATA)
                enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                rebuild_rag_index()
                logger.info("Cleared ALL files and ACTIVE_DATA for brand new case")
            except Exception as e:
                logger.error(f"Error resetting engines: {e}")
        elif is_new_session:
            # Creating a new session for an existing case (user chose "Create New" after warning)
            logger.info(f"Creating new session for existing case {case_id} - clearing ACTIVE_DATA (files remain on disk)")
            
            # Clear ACTIVE_DATA but keep files on disk (they belong to previous session)
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            
            # Reset engines with empty data
            try:
                nl_engine.update_data(ACTIVE_DATA)
                enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                rebuild_rag_index()
                logger.info("Cleared ACTIVE_DATA for new session (files remain on disk)")
            except Exception as e:
                logger.error(f"Error resetting engines: {e}")
        
        # Get current user ID for security
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        # Verify case belongs to current user
        if case.get('created_by') != session.get('username'):
            return jsonify({"status": "ERROR", "message": "Access denied: Case does not belong to you"}), 403
        
        # Create session
        import uuid
        session_id = str(uuid.uuid4())
        title = data.get('title', f"Investigation - {case['case_name']}")
        
        success, error_msg = create_session(session_id, case_id=case_id, title=title, user_id=user_id)
        if success:
            # Update session access time immediately when created
            update_session_access(session_id)
            # Also update the case's updated_at timestamp when investigation is opened
            # This makes "Last Updated" and "Last Opened" synchronized
            # update_case already imported at top
            update_case(case_id)  # This will update updated_at to current time
            return jsonify({
                "status": "SUCCESS",
                "session_id": session_id,
                "case_id": case_id,
                "evi_scan_url": f"/evi-scan?session_id={session_id}",
                "message": "Session created successfully"
            })
        else:
            error_message = error_msg or "Failed to create session"
            logger.error(f"Failed to create session: {error_message}")
            return jsonify({"status": "ERROR", "message": error_message})
    except Exception as e:
        logger.error(f"Error creating case session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/chat/stream', methods=['POST'])
def chat_query_stream():
    """Forensic AI Chat Assistant with Streaming Response - Real-time token streaming like ChatGPT."""
    import time
    import json as json_lib
    start_time = time.time()
    
    def calculate_response_time():
        """Calculate and format response time."""
        elapsed = time.time() - start_time
        return round(elapsed, 2)
    
    def generate_stream():
        """Generator function that yields streaming tokens."""
        # SSE format requires double newline
        sse_end = "\n\n"
        
        try:
            data = request.get_json() or {}
            query = (data.get('query') or data.get('message') or '')
            # Ensure query is a string and not None
            if query is None:
                query = ''
            if not isinstance(query, str):
                query = str(query) if query else ''
            query = query.strip()
            use_json_extraction = data.get('use_json', False)  # New option: let LLM extract from JSON
            
            # CRITICAL: Rewrite vague questions to prevent hallucination
            original_query = query
            query = rewrite_vague_query(query)
            if query != original_query:
                logger.info(f"✅ Query rewritten: '{original_query}' → '{query}'")
            
            # CRITICAL: Log the received query
            logger.info(f"🔍 RECEIVED QUERY FROM CLIENT: {repr(query)}")
            logger.info(f"🔍 Query length: {len(query)} characters")
            logger.info(f"🔍 Query type: {type(query)}")
            logger.info(f"🔍 Request data keys: {list(data.keys())}")
            
            if not query:
                logger.error(f"❌ ERROR: Empty query received from client! Data: {data}")
                error_data = json_lib.dumps({'type': 'error', 'message': 'No query provided', 'response': 'I need a question to investigate. What would you like me to analyze?'})
                yield f"data: {error_data}{sse_end}"
                return
            
            data_src = get_current_data()
            if not data_src:
                error_data = json_lib.dumps({'type': 'error', 'message': 'Upload a UFDR JSON file first.', 'response': 'I need UFDR data to investigate. Please upload a forensic report first.'})
                yield f"data: {error_data}{sse_end}"
                return
            
            # Initialize session early (needed for Qwen2.5-VL processing)
            if 'session_id' not in session:
                import uuid
                session['session_id'] = str(uuid.uuid4())
                CHAT_HISTORIES[session['session_id']] = []
            
            session_id = session['session_id']
            
            # Check if query needs Qwen2.5-VL (images/videos) - STREAMING ENDPOINT
            use_qwen_vl = False
            if USE_QWEN_VL and has_images_or_videos(data_src) and query:
                # Check if query is image/video related
                query_lower = query.lower() if query else ""
                image_keywords = ['image', 'photo', 'picture', 'screenshot', 'visual', 'see', 'show', 'what', 'describe']
                video_keywords = ['video', 'footage', 'recording', 'clip', 'movie']
                
                if query_lower and any(kw in query_lower for kw in image_keywords + video_keywords):
                    use_qwen_vl = True
                    logger.info("Using Qwen2.5-VL-7B for multimodal analysis (streaming)")
            
            # Try Qwen2.5-VL first if needed (for streaming, we'll return a single response)
            if use_qwen_vl:
                try:
                    chat_history = CHAT_HISTORIES.get(session_id, [])
                    response, error = process_with_qwen_vl(query, data_src, chat_history)
                    if response:
                        # Store in chat history
                        if session_id not in CHAT_HISTORIES:
                            CHAT_HISTORIES[session_id] = []
                        CHAT_HISTORIES[session_id].append({"role": "user", "content": query})
                        CHAT_HISTORIES[session_id].append({"role": "assistant", "content": response})
                        
                        # Persist to database
                        persist_chat_message(session_id, "user", query)
                        persist_chat_message(session_id, "assistant", response, metadata={"model_used": "Qwen2.5-VL-7B", "multimodal": True})
                        
                        # Send response as streaming (single chunk for Qwen)
                        response_data = json_lib.dumps({
                            'type': 'token',
                            'content': response,
                            'model_used': 'Qwen2.5-VL-7B',
                            'multimodal': True
                        })
                        yield f"data: {response_data}{sse_end}"
                        
                        # Send done signal
                        done_data = json_lib.dumps({
                            'type': 'done',
                            'response_time': calculate_response_time(),
                            'model_used': 'Qwen2.5-VL-7B',
                            'multimodal': True
                        })
                        yield f"data: {done_data}{sse_end}"
                        return
                    elif error:
                        logger.warning(f"Qwen2.5-VL processing failed: {error}, falling back to LLM")
                except Exception as e:
                    logger.error(f"Error in Qwen2.5-VL processing: {e}", exc_info=True)
                    # Fall through to LLM processing
            
            if not USE_LLM:
                error_data = json_lib.dumps({'type': 'error', 'message': 'LLM service unavailable', 'response': 'LLM integration is disabled. Please enable it in the configuration.'})
                yield f"data: {error_data}{sse_end}"
                return
            
            try:
                # Quick health check
                try:
                    health_check = requests.get("http://localhost:1234/v1/models", timeout=5)
                    if not health_check.ok:
                        error_data = json_lib.dumps({'type': 'error', 'message': f'LM Studio health check failed: HTTP {health_check.status_code}'})
                        yield f"data: {error_data}{sse_end}"
                        return
                except requests.exceptions.ConnectionError:
                    error_msg = '🔌 **CONNECTION ERROR**\n\nCannot connect to LM Studio. Please start the LM Studio server.'
                    error_data = json_lib.dumps({'type': 'error', 'message': 'Cannot connect to LM Studio. Is the server running?', 'response': error_msg})
                    yield f"data: {error_data}{sse_end}"
                    return
                
                # Initialize chat history if needed
                if session_id not in CHAT_HISTORIES:
                    CHAT_HISTORIES[session_id] = []
                
                # Get chat history
                chat_history = CHAT_HISTORIES.get(session_id, [])
                
                # Save user query to history BEFORE sending to LLM (for proper follow-up context)
                # This ensures the query is available for the next follow-up even if the response fails
                CHAT_HISTORIES[session_id].append({
                    "role": "user",
                    "content": query,
                    "timestamp": datetime.now().isoformat()
                })
                
                # If query is overly broad, return refinement suggestions instead of a generic LLM answer
                # Broad query detection removed per user request
                
                # Get data context and image citations
                data_context = ""
                image_citations = []
                if data_src:
                    # DIAGNOSTIC: Log what data we have
                    logger.info(f"📊 Data source check: {len(data_src)} file(s) in ACTIVE_DATA")
                    logger.info(f"📊 ACTIVE_DATA keys: {list(data_src.keys())}")
                    
                    # CRITICAL: Check if this is a summary/overview question
                    is_summary_query = is_query_too_broad(query)
                    
                    if is_summary_query:
                        # Generate pre-summarized overview instead of raw data dump
                        logger.info("📊 Summary query detected - generating forensic overview instead of raw data")
                        overview = generate_forensic_overview(data_src)
                        
                        # Format as structured data for LLM
                        data_context = f"""FORENSIC OVERVIEW (AUTHORITATIVE):
- Contacts: {overview['contacts_count']}
- Messages: {overview['messages_count']}
- Calls: {overview['calls_count']}
- Locations: {overview['locations_count']}
- Date Range: {overview['date_range'] or 'Not available'}
- Platforms: {', '.join(overview['top_apps']) if overview['top_apps'] else 'Not available'}
- Most Active Contacts: {', '.join(overview['most_active_contacts']) if overview['most_active_contacts'] else 'Not available'}"""
                        
                        logger.info(f"✅ Generated forensic overview: {overview}")
                    # NEW: Option to let LLM extract directly from JSON
                    elif use_json_extraction:
                        logger.info("Using JSON extraction mode in stream - LLM will extract data directly from JSON")
                        for filename, data in data_src.items():
                            # Skip metadata keys like '_zip_info' - only process actual UFDR data
                            if filename.startswith('_'):
                                logger.debug(f"Skipping metadata key: {filename}")
                                continue
                            
                            if isinstance(data, dict):
                                try:
                                    # DIAGNOSTIC: Log data structure
                                    logger.info(f"📊 Processing file: {filename}")
                                    logger.info(f"📊 Data keys: {list(data.keys())}")
                                    
                                    # Check for devices array
                                    if 'devices' in data:
                                        devices = data['devices']
                                        logger.info(f"📊 Found {len(devices)} device(s) in data")
                                        for i, device in enumerate(devices):
                                            if isinstance(device, dict):
                                                contacts_count = len(device.get('contacts', []))
                                                messages_count = len(device.get('messages', []))
                                                calls_count = len(device.get('call_logs', []))
                                                locations_count = len(device.get('locations', []))
                                                logger.info(f"📊 Device {i+1}: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                    else:
                                        # Check flat structure
                                        contacts_count = len(data.get('contacts', []))
                                        messages_count = len(data.get('messages', []))
                                        calls_count = len(data.get('call_logs', []))
                                        locations_count = len(data.get('locations', []))
                                        logger.info(f"📊 Flat structure: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                        if locations_count > 0:
                                            logger.info(f"📍 Location data found at root level: {locations_count} location records")
                                            sample_loc = data.get('locations', [])[0] if data.get('locations') else {}
                                            logger.info(f"📍 Sample location: {sample_loc.get('address', 'N/A')} at ({sample_loc.get('latitude', 'N/A')}, {sample_loc.get('longitude', 'N/A')})")
                                    
                                    # Ensure query is safe for prepare_json_for_llm
                                    safe_query = query if query and isinstance(query, str) else ""
                                    json_context = prepare_json_for_llm(data, safe_query, max_chars=8000)
                                    logger.info(f"📊 Prepared JSON context: {len(json_context)} characters")
                                    if data_context:
                                        data_context += "\n\n--- Additional Data ---\n\n"
                                    data_context += json_context
                                except Exception as e:
                                    logger.error(f"❌ Error preparing JSON for LLM: {e}", exc_info=True)
                                    # Fallback to semantic extraction (Magnet AXIOM style)
                                    safe_query = query if query and isinstance(query, str) else ""
                                    try:
                                        extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"🔍 Semantic extraction (fallback): {len(extracted_context)} characters")
                                    except Exception as e:
                                        logger.warning(f"Semantic extraction failed: {e}, using enhanced extractor")
                                        extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    data_context = extracted_context
                    else:
                        # Original approach: Use enhanced extractor
                        for filename, data in data_src.items():
                            # Skip metadata keys like '_zip_info' - only process actual UFDR data
                            if filename.startswith('_'):
                                logger.debug(f"Skipping metadata key: {filename}")
                                continue
                            
                            if isinstance(data, dict):
                                # DIAGNOSTIC: Log data structure
                                logger.info(f"📊 Processing file: {filename}")
                                logger.info(f"📊 Data keys: {list(data.keys())}")
                                
                                # Check for devices array
                                if 'devices' in data:
                                    devices = data['devices']
                                    logger.info(f"📊 Found {len(devices)} device(s) in data")
                                    for i, device in enumerate(devices):
                                        if isinstance(device, dict):
                                            contacts_count = len(device.get('contacts', []))
                                            messages_count = len(device.get('messages', []))
                                            calls_count = len(device.get('call_logs', []))
                                            locations_count = len(device.get('locations', []))
                                            logger.info(f"📊 Device {i+1}: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                else:
                                    # Check flat structure
                                    contacts_count = len(data.get('contacts', []))
                                    messages_count = len(data.get('messages', []))
                                    calls_count = len(data.get('call_logs', []))
                                    locations_count = len(data.get('locations', []))
                                    logger.info(f"📊 Flat structure: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                    if locations_count > 0:
                                        logger.info(f"📍 Location data found at root level: {locations_count} location records")
                                        sample_loc = data.get('locations', [])[0] if data.get('locations') else {}
                                        logger.info(f"📍 Sample location: {sample_loc.get('address', 'N/A')} at ({sample_loc.get('latitude', 'N/A')}, {sample_loc.get('longitude', 'N/A')})")
                                
                                # Ensure query is safe
                                safe_query = query if query and isinstance(query, str) else ""
                                # Use semantic extractor (Magnet AXIOM style) - extracts ALL relevant data
                                try:
                                    extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                    # Truncate to fit context window
                                    extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    logger.info(f"🔍 Semantic extraction: {len(extracted_context)} characters")
                                    logger.debug(f"📊 Extracted context preview (first 500 chars): {extracted_context[:500]}")
                                except Exception as e:
                                    logger.warning(f"Semantic extraction failed: {e}, falling back to enhanced extractor")
                                    extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                    # Truncate to fit context window
                                    extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    logger.info(f"📊 Fallback extraction: {len(extracted_context)} characters")
                                data_context = extracted_context
                            
                            # Extract image citations
                            try:
                                if query and isinstance(query, str):  # Safety check
                                    image_citations = image_citation_extractor.extract_image_citations(data, query)
                                    if image_citations and image_citation_extractor.is_image_query(query):
                                        image_info = image_citation_extractor.format_image_citations(image_citations)
                                        data_context += image_info
                            except Exception as e:
                                logger.warning(f"Error extracting image citations in stream: {e}")
                            
                            break
                
                # DIAGNOSTIC: Log final context
                if data_context:
                    logger.info(f"📊 Final data_context length: {len(data_context)} characters")
                    logger.debug(f"📊 Final data_context preview (first 1000 chars):\n{data_context[:1000]}")
                else:
                    logger.warning(f"⚠️ WARNING: data_context is EMPTY! LLM will not receive any UFDR data!")
                
                # Detect query language and add language instruction
                from utils.language_detector import detect_language, get_language_instruction
                detected_language = detect_language(query)
                language_instruction = get_language_instruction(detected_language)
                
                # Prepare messages
                messages = []
                
                messages.append({
                    "role": "system",
                    "content": f"""You are an elite digital forensics analyst with expertise in mobile device forensics, communication analysis, and evidence investigation. Your role is to conduct thorough, professional forensic examinations of UFDR (Universal Forensic Data Report) files.

🌐 LANGUAGE REQUIREMENT: {language_instruction}
You MUST respond in the same language as the user's query. Match the user's language exactly.

⚠️ CRITICAL: ALWAYS answer the user's specific question directly. Your entire response must focus on what the user asked. Do not provide generic analysis that doesn't address the specific query.

CORE CAPABILITIES:
- Deep analysis of messages (SMS, WhatsApp, iMessage), call logs, contacts, and device metadata
- Timeline reconstruction and chronological event analysis
- Relationship mapping between contacts, communications, and activities
- Pattern recognition for suspicious behaviors, security threats, and anomalies
- Evidence correlation and cross-referencing across multiple data sources
- Chain of custody documentation and evidence integrity verification

ANALYSIS METHODOLOGY:
1. QUERY FOCUS: First, identify the user's specific question and ensure your entire response addresses it
2. EVIDENCE IDENTIFICATION: Identify all relevant evidence related to the user's query
3. CONTEXTUAL ANALYSIS: Examine evidence within temporal, relational, and behavioral context
4. PATTERN DETECTION: Identify communication patterns, frequency anomalies, timing patterns
5. CORRELATION: Connect related evidence across different data types (messages↔calls↔contacts)
6. RISK ASSESSMENT: Evaluate security concerns, suspicious activities, and potential threats
7. ACTIONABLE INTELLIGENCE: Provide specific, actionable findings with evidence citations

RESPONSE REQUIREMENTS:
- ALWAYS answer the user's specific question - do not provide unrelated information
- Always cite specific evidence (dates, timestamps, contact names, message content, call durations)
- Include timestamps and temporal context for all findings
- Use professional forensic terminology (e.g., "artifact", "evidence", "chain of custody", "metadata")
- Maintain objectivity - distinguish between facts and inferences
- Provide confidence levels when making inferences
- Structure responses with clear sections for different types of analysis
- If the user asks about specific people or relationships, focus ONLY on those people/relationships

Your goal is to provide comprehensive, professional forensic analysis that directly answers the user's question and would stand up in a legal or investigative context."""
                })
                
                # CRITICAL: Only include chat history for conversational follow-ups, NOT for forensic analysis
                # Chat history causes hallucination in 3B models when combined with forensic data
                from utils.query_analyzer import query_analyzer

                is_follow_up = query_analyzer.is_follow_up_question(query, CHAT_HISTORIES.get(session_id, []))

                # Only include history for true follow-up questions (conversational continuity)
                if is_follow_up and session_id in CHAT_HISTORIES and CHAT_HISTORIES[session_id]:
                    # Get all history except the last message (which is the current query we just added)
                    history_messages = CHAT_HISTORIES[session_id][:-1] if len(CHAT_HISTORIES[session_id]) > 1 else []
                    for msg in history_messages:
                        role = msg.get("role", "user")
                        if role not in ["user", "assistant"]:
                            role = "user" if role == "user" else "assistant"
                        content = msg.get("content", "")
                        if content:  # Only add non-empty messages
                            messages.append({
                                "role": role,
                                "content": content
                            })
                    logger.info(f"📝 Including {len(history_messages)} previous messages (follow-up question detected)")
                else:
                    logger.info(f"🔒 Excluding chat history (forensic query - prevents hallucination)")
                
                # Add user query with data context - emphasize the query
                # (The query is already in CHAT_HISTORIES, but we add it here with data context)
                if data_context:
                    # Dynamic context-aware truncation
                    # Calculate actual available space based on system message, query, and response buffer
                    # Model has LLM_CONTEXT_LENGTH tokens total
                    
                    # Estimate system message size (first message)
                    system_chars = len(messages[0].get('content', '')) if messages else 0
                    system_tokens = int(system_chars / 1.67)
                    
                    # Estimate query size
                    query_chars = len(query)
                    query_tokens = int(query_chars / 1.67)
                    
                    # Reserve tokens for response (minimum 200 tokens for response)
                    response_reserve = 200
                    
                    # Calculate available space for data
                    # Total: LLM_CONTEXT_LENGTH tokens
                    # Used: system + query + response buffer
                    # Available: LLM_CONTEXT_LENGTH - system - query - response
                    available_tokens = LLM_CONTEXT_LENGTH - system_tokens - query_tokens - response_reserve
                    
                    # Add some safety margin (reduce by 10% to be safe)
                    available_tokens = int(available_tokens * 0.9)
                    
                    # Ensure minimum available space (at least 500 tokens)
                    available_tokens = max(500, available_tokens)
                    
                    logger.info(f"📊 Context calculation: System={system_tokens} tokens, Query={query_tokens} tokens, Available for data={available_tokens} tokens (out of {LLM_CONTEXT_LENGTH} total)")
                    
                    # Truncate data_context to fit available space
                    # Convert tokens to characters (1 token ≈ 1.67 characters)
                    available_chars = int(available_tokens * 1.67)
                    
                    if len(data_context) > available_chars:
                        logger.warning(f"⚠️ Truncating data from {len(data_context)} to {available_chars} characters to fit {LLM_CONTEXT_LENGTH} token context")
                        # Use truncate_for_context with calculated available space
                        data_context = truncate_for_context(data_context, max_tokens=LLM_CONTEXT_LENGTH, reserved_tokens=(LLM_CONTEXT_LENGTH - available_tokens))
                    else:
                        logger.info(f"✅ Data fits within context: {len(data_context)} characters")
                    
                    user_message = f"""QUESTION:
{query}

FORENSIC DATA (AUTHORITATIVE):
{data_context}"""
                else:
                    user_message = query
                messages.append({
                    "role": "user",
                    "content": user_message
                })
                
                # CRITICAL: Verify query is in the messages
                logger.info(f"🔍 QUERY VERIFICATION:")
                logger.info(f"   - Original query: {repr(query[:100])}")
                logger.info(f"   - Query in last message: {repr(messages[-1]['content'][:100])}")
                logger.info(f"   - Query found in last message: {'QUESTION:' in messages[-1]['content'] or query[:50] in messages[-1]['content']}")
                logger.info(f"   - Total messages: {len(messages)}")
                logger.info(f"   - Last message role: {messages[-1]['role']}")
                logger.info(f"   - Last message starts with: {repr(messages[-1]['content'][:50])}")
                
                # Estimate total token count (rough: 1 token ≈ 1.67 characters)
                total_chars = sum(len(msg.get('content', '')) for msg in messages)
                estimated_tokens = int(total_chars / 1.67)
                
                # Warn if prompt might exceed context limits
                if estimated_tokens > int(LLM_CONTEXT_LENGTH * 0.9):
                    logger.warning(f"⚠️ Large prompt detected: ~{estimated_tokens} tokens ({total_chars} chars)")
                    logger.warning(f"   - This may exceed models with {LLM_CONTEXT_LENGTH} token context limits")
                    logger.warning(f"   - Consider increasing model context length in LM Studio to {LLM_CONTEXT_LENGTH * 2}+ tokens")
                
                # Send initial metadata
                start_data = json_lib.dumps({'type': 'start', 'message': 'Starting analysis...'})
                yield f"data: {start_data}{sse_end}"
                
                # Make streaming request to LM Studio
                llm_start = time.time()
                logger.info(f"📤 Sending request to LM Studio: {LLM_URL}, model: {LLM_MODEL}, messages: {len(messages)}")
                logger.info(f"📤 System message length: {len(messages[0]['content'])} characters")
                logger.info(f"📤 User message (last) length: {len(messages[-1]['content'])} characters")
                logger.info(f"📤 Total prompt: {total_chars} characters (~{estimated_tokens} tokens)")
                logger.info(f"📤 User query in message: {repr(query[:100])}")
                logger.debug(f"📤 First message preview: {messages[0]['content'][:200]}...")
                logger.debug(f"📤 Last message preview: {messages[-1]['content'][:500]}...")
                
                # DIAGNOSTIC: Verify data is in the prompt
                last_message_content = messages[-1]['content']
                if 'FORENSIC DATA' in last_message_content or 'FORENSIC DATA (JSON FORMAT)' in last_message_content:
                    data_section_start = last_message_content.find('FORENSIC DATA')
                    if data_section_start != -1:
                        data_section = last_message_content[data_section_start:data_section_start+500]
                        logger.info(f"✅ Data section found in prompt (starts at position {data_section_start})")
                        logger.debug(f"📊 Data section preview: {data_section}")
                        # Check if data section has actual content (more lenient check)
                        # The data might be formatted differently, so check for various indicators
                        has_json_indicators = ('{' in data_section or '[' in data_section or 
                                              '"contacts"' in data_section or '"messages"' in data_section or
                                              '"call_logs"' in data_section or len(data_section) > 200)
                        if not has_json_indicators:
                            logger.warning(f"⚠️ Data section preview may be malformed (first 500 chars), but full data context is {len(data_context)} chars")
                        else:
                            logger.debug(f"✅ Data section preview looks valid")
                    else:
                        logger.error(f"❌ ERROR: 'FORENSIC DATA' marker not found in prompt!")
                else:
                    logger.error(f"❌ ERROR: 'FORENSIC DATA' section not found in prompt! LLM will not receive data!")
                
                # Check if data_context was actually included
                if data_context and data_context.strip():
                    if data_context in last_message_content:
                        logger.info(f"✅ Verified: data_context is included in prompt ({len(data_context)} chars)")
                    else:
                        logger.error(f"❌ ERROR: data_context is NOT in the prompt! This is a critical bug!")
                else:
                    logger.error(f"❌ ERROR: data_context is empty! LLM cannot access any data!")
                
                # Prepare request payload
                # CRITICAL: 3B models MUST be cold and short for forensic work
                request_payload = {
                    "model": LLM_MODEL,
                    "messages": messages,
                    "temperature": 0.2,  # Lower temperature for more deterministic, less hallucination
                    "max_tokens": 1200,  # Shorter responses prevent fabrication
                    "stream": True  # Enable streaming
                }
                
                logger.info(f"📤 Request details: model={LLM_MODEL}, messages={len(messages)}, prompt_length={len(messages[-1]['content'])}, max_tokens=1200, temperature=0.2")
                
                resp = requests.post(
                    LLM_URL,
                    json=request_payload,
                    timeout=90,
                    stream=True  # Important: stream the response
                )
                
                logger.info(f"📥 LM Studio response status: {resp.status_code}")
                
                if not resp.ok:
                    error_msg = resp.text[:500] if resp.text else "No error message"
                    logger.error(f"❌ LM Studio API error: HTTP {resp.status_code}, Response: {error_msg}")
                    error_data = json_lib.dumps({'type': 'error', 'message': f'LM Studio API error: HTTP {resp.status_code}', 'response': f'❌ **API ERROR**\n\nLM Studio returned HTTP {resp.status_code}.\n\nError: {error_msg}'})
                    yield f"data: {error_data}{sse_end}"
                    return
                
                # Stream tokens from LM Studio
                full_response = ""
                buffer = ""
                chunk_count = 0
                content_chunks_received = 0
                non_data_lines = 0
                
                logger.info(f"🔄 Starting to stream response from LM Studio...")
                
                for line in resp.iter_lines():
                    if line:
                        line = line.decode('utf-8')
                        chunk_count += 1
                        
                        # Log first few lines for debugging
                        if chunk_count <= 10:  # Increased from 5 to 10 for better debugging
                            logger.info(f"📥 Stream line {chunk_count}: {line[:300]}")
                        
                        # LM Studio uses Server-Sent Events format
                        if line.startswith('data: '):
                            try:
                                data_str = line[6:]  # Remove 'data: ' prefix
                                if data_str.strip() == '[DONE]':
                                    logger.info(f"✅ Received [DONE] signal after {chunk_count} chunks")
                                    break
                                
                                chunk_data = json_lib.loads(data_str)
                                
                                # Enhanced debugging for empty responses
                                if chunk_count <= 5:
                                    logger.info(f"🔍 Chunk {chunk_count} structure: {json_lib.dumps(chunk_data, indent=2)[:500]}")
                                
                                # Check for error responses from LM Studio
                                if 'error' in chunk_data:
                                    error_info = chunk_data.get('error', {})
                                    error_message = error_info.get('message', 'Unknown error from LM Studio')
                                    logger.error(f"❌ LM Studio returned an error: {error_message}")
                                    
                                    # Check if it's a context length error
                                    if 'context' in error_message.lower() or 'token' in error_message.lower() or str(LLM_CONTEXT_LENGTH) in error_message:
                                        error_msg = f"""⚠️ **CONTEXT LENGTH EXCEEDED**

The prompt is too long for the model's context window.

**Error Details:**
{error_message}

**Problem:**
- Your model in LM Studio is loaded with a context length of **{LLM_CONTEXT_LENGTH} tokens**
- The current prompt requires approximately **{int(len(messages[-1]['content']) / 1.67)} tokens**
- This exceeds the model's capacity

**Solutions:**

1. **Increase Model Context Length (Recommended):**
   - In LM Studio, go to the model settings
   - Increase the "Context Length" to at least **{LLM_CONTEXT_LENGTH * 2}** or **{LLM_CONTEXT_LENGTH * 4}** tokens
   - Reload the model with the new context length
   - Or set environment variable: `LLM_CONTEXT_LENGTH={LLM_CONTEXT_LENGTH * 2}` and restart the server

2. **Use a Model with Larger Context:**
   - Switch to a model that supports larger contexts (e.g., Qwen2.5-7B-Instruct with 32K context)
   - Or use a model specifically designed for longer contexts

3. **Reduce Data Size:**
   - Try a more specific query that requires less data
   - The system will automatically truncate data, but very large cases may still exceed limits

**Current Prompt Size:** {len(messages[-1]['content'])} characters (~{int(len(messages[-1]['content']) / 1.67)} tokens)"""
                                    else:
                                        error_msg = f"""⚠️ **LM STUDIO ERROR**

The LLM server returned an error:

**Error:** {error_message}

**Troubleshooting:**
1. Check if LM Studio is running and the model is loaded
2. Verify the model is compatible with the API
3. Check LM Studio logs for more details
4. Try restarting LM Studio server"""
                                    
                                    error_data = json_lib.dumps({'type': 'error', 'message': 'LM Studio error', 'response': error_msg})
                                    yield f"data: {error_data}{sse_end}"
                                    return
                                
                                choices = chunk_data.get('choices', [])
                                
                                if not choices:
                                    logger.warning(f"⚠️ No choices in chunk {chunk_count}, chunk_data keys: {list(chunk_data.keys())}, full chunk: {json_lib.dumps(chunk_data)[:200]}")
                                    continue
                                
                                delta = choices[0].get('delta', {})
                                
                                # Enhanced debugging for delta structure
                                if chunk_count <= 5:
                                    logger.info(f"🔍 Chunk {chunk_count} delta keys: {list(delta.keys())}, delta content: {repr(delta.get('content', ''))[:100]}")
                                
                                content = delta.get('content', '')
                                
                                # Check for role in delta (some models send role first)
                                if 'role' in delta and not content:
                                    logger.debug(f"📝 Chunk {chunk_count} contains role: {delta.get('role')}, no content yet")
                                
                                if content:
                                    content_chunks_received += 1
                                    full_response += content
                                    
                                    # Send token to client
                                    token_data = json_lib.dumps({'type': 'token', 'content': content})
                                    yield f"data: {token_data}{sse_end}"
                                
                                # Check if this is the final chunk
                                finish_reason = choices[0].get('finish_reason')
                                if finish_reason:
                                    logger.info(f"✅ Stream finished with reason: {finish_reason} after {chunk_count} chunks, {content_chunks_received} content chunks")
                                    if finish_reason != 'stop' and finish_reason != 'length':
                                        logger.warning(f"⚠️ Unusual finish_reason: {finish_reason}")
                                    break
                            except json_lib.JSONDecodeError as e:
                                logger.warning(f"⚠️ Failed to parse SSE chunk {chunk_count}: {e}, line: {line[:100]}")
                                continue
                            except Exception as e:
                                logger.error(f"❌ Error processing stream chunk {chunk_count}: {e}", exc_info=True)
                                continue
                        else:
                            non_data_lines += 1
                            if non_data_lines <= 3:
                                logger.debug(f"📥 Non-data line {non_data_lines}: {line[:100]}")
                
                llm_time = time.time() - llm_start
                logger.info(f"📊 Stream complete: {len(full_response)} characters received, {content_chunks_received} content chunks, {chunk_count} total chunks, {non_data_lines} non-data lines, {llm_time:.2f}s elapsed")
                
                # Check if response is empty
                if not full_response or len(full_response.strip()) == 0:
                    logger.error(f"❌ CRITICAL: Empty response received from LLM!")
                    logger.error(f"   - Total chunks processed: {chunk_count}")
                    logger.error(f"   - Content chunks received: {content_chunks_received}")
                    logger.error(f"   - Non-data lines: {non_data_lines}")
                    logger.error(f"   - Response time: {llm_time:.2f}s")
                    logger.error(f"   - Prompt length: {len(messages[-1]['content'])} characters")
                    logger.error(f"   - This suggests LM Studio is not generating content or stream format is incorrect")
                    
                    # Send error message to client
                    error_msg = f"""⚠️ **EMPTY RESPONSE DETECTED**

The LLM did not generate any content. 

**Diagnostics:**
- Total chunks received: {chunk_count}
- Content chunks: {content_chunks_received}
- Non-data lines: {non_data_lines}
- Response time: {llm_time:.2f}s
- Prompt length: {len(messages[-1]['content'])} characters

**Possible causes:**
1. LM Studio model not responding properly
2. Prompt too long
3. Model configuration issue
4. Stream format mismatch

**Try:**
1. Check if LM Studio is running and model is loaded
2. Try a shorter query
3. Restart LM Studio server
4. Check LM Studio logs for errors"""
                    
                    error_data = json_lib.dumps({'type': 'error', 'message': 'Empty response from LLM', 'response': error_msg})
                    yield f"data: {error_data}{sse_end}"
                    return
                
                # Store in chat history
                # Note: datetime is already imported at module level (line 27)
                # User query was already added to CHAT_HISTORIES before sending to LLM
                # Now add the assistant response
                if session_id not in CHAT_HISTORIES:
                    CHAT_HISTORIES[session_id] = []
                
                CHAT_HISTORIES[session_id].append({
                    "role": "assistant",
                    "content": full_response,
                    "timestamp": datetime.now().isoformat()
                })
                
                # NO LIMIT - Keep all chat history
                # Removed limit to allow full conversation context
                
                # Calculate confidence
                intent_strength = confidence_calculator.calculate_intent_strength(query, "llm_query")
                query_complexity = confidence_calculator.calculate_query_complexity(query)
                confidence = confidence_calculator.calculate_confidence(
                    retrieval_scores=[0.9],
                    intent_strength=intent_strength,
                    data_completeness=1.0,
                    query_complexity=query_complexity,
                    response_quality=0.95
                )
                
                # Prepare image citations for response
                image_citations_response = []
                for citation in image_citations:
                    image_citations_response.append({
                        "filename": citation.get("filename", ""),
                        "relative_path": citation.get("relative_path", ""),
                        "path": citation.get("path", ""),
                        "context": citation.get("context", ""),
                        "relevance_score": citation.get("relevance_score", 0)
                    })
                
                # Use full response as-is
                display_response = full_response
                
                # Persist to database (after confidence is calculated) - store original for audit
                persist_chat_message(session_id, "user", query)
                persist_chat_message(session_id, "assistant", full_response, metadata={
                    "llm_used": True,
                    "rag_used": False,
                    "confidence": confidence,
                    "response_time": calculate_response_time(),
                    "model_used": LLM_MODEL,
                    "response_length": len(full_response)
                    })
                
                # Send completion message with metadata and image citations
                done_data = json_lib.dumps({
                    'type': 'done', 
                    'confidence': confidence, 
                    'response_time': calculate_response_time(), 
                    'llm_used': True,
                    'image_citations': image_citations_response,
                    'has_images': len(image_citations_response) > 0,
                    'response_length': len(display_response)
                })
                yield f"data: {done_data}{sse_end}"
                logger.info(f"✅ Stream completed successfully: {len(display_response)} characters, confidence: {confidence:.3f}")
                
            except requests.exceptions.Timeout:
                timeout_msg = '⏱️ **TIMEOUT ERROR**\n\nThe request to LM Studio timed out after 90 seconds.'
                error_data = json_lib.dumps({'type': 'error', 'message': 'Request timed out', 'response': timeout_msg})
                yield f"data: {error_data}{sse_end}"
            except requests.exceptions.ConnectionError:
                conn_msg = '🔌 **CONNECTION ERROR**\n\nCannot connect to LM Studio. Please start the LM Studio server.'
                error_data = json_lib.dumps({'type': 'error', 'message': 'Cannot connect to LM Studio', 'response': conn_msg})
                yield f"data: {error_data}{sse_end}"
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"Streaming error: {str(e)}\nFull traceback:\n{error_trace}")
                error_msg = f'❌ **ERROR**\n\nAn error occurred: {str(e)}'
                error_data = json_lib.dumps({'type': 'error', 'message': str(e), 'response': error_msg})
                yield f"data: {error_data}{sse_end}"
                
        except Exception as e:
            logger.error(f"Stream generation error: {str(e)}")
            error_msg = f'Error in chat query: {str(e)}'
            error_data = json_lib.dumps({'type': 'error', 'message': str(e), 'response': error_msg})
            yield f"data: {error_data}{sse_end}"
    
    return Response(stream_with_context(generate_stream()), mimetype='text/event-stream')

@app.route('/api/chat', methods=['POST'])
def chat_query():
    """Forensic AI Chat Assistant - Conversational Investigator."""
    import time
    start_time = time.time()
    
    def calculate_response_time():
        """Calculate and format response time."""
        elapsed = time.time() - start_time
        return round(elapsed, 2)
    
    try:
        data = request.get_json() or {}
        query = (data.get('query') or data.get('message') or '')
        # Ensure query is a string and not None
        if query is None:
            query = ''
        if not isinstance(query, str):
            query = str(query) if query else ''
        query = query.strip()
        use_json_extraction = data.get('use_json', False)  # New option: let LLM extract from JSON
        
        # CRITICAL: Rewrite vague questions to prevent hallucination
        original_query = query
        query = rewrite_vague_query(query)
        if query != original_query:
            logger.info(f"✅ Query rewritten: '{original_query}' → '{query}'")
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided",
                "response": "I need a question to investigate. What would you like me to analyze?",
                "confidence": 0.0,
                "response_time": calculate_response_time()
            })
        
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first.",
                "response": "I need UFDR data to investigate. Please upload a forensic report first.",
                "confidence": 0.0,
                "response_time": calculate_response_time()
            })

        # If query is overly broad, return refinement suggestions instead of a generic LLM answer
        # Broad query detection removed per user request
        
        # Initialize session if needed
        if 'session_id' not in session:
            import uuid
            session['session_id'] = str(uuid.uuid4())
        session_id = session['session_id']
        
        # Initialize chat history if needed
        if session_id not in CHAT_HISTORIES:
            CHAT_HISTORIES[session_id] = []
        
        # Save user query to history BEFORE sending to LLM (for proper follow-up context)
        CHAT_HISTORIES[session_id].append({
            "role": "user",
            "content": query,
            "timestamp": datetime.now().isoformat()
        })
        
        # Check if query needs Qwen2.5-VL (images/videos)
        use_qwen_vl = False
        if USE_QWEN_VL and has_images_or_videos(data_src) and query:
            # Check if query is image/video related
            query_lower = query.lower() if query else ""
            image_keywords = ['image', 'photo', 'picture', 'screenshot', 'visual', 'see', 'show', 'what', 'describe']
            video_keywords = ['video', 'footage', 'recording', 'clip', 'movie']
            
            if query_lower and any(kw in query_lower for kw in image_keywords + video_keywords):
                use_qwen_vl = True
                logger.info("Using Qwen2.5-VL-7B for multimodal analysis")
        
        # Try Qwen2.5-VL first if needed
        if use_qwen_vl:
            chat_history = CHAT_HISTORIES.get(session_id, [])
            response, error = process_with_qwen_vl(query, data_src, chat_history)
            if response:
                # Store in chat history
                if session_id not in CHAT_HISTORIES:
                    CHAT_HISTORIES[session_id] = []
                CHAT_HISTORIES[session_id].append({"role": "user", "content": query})
                CHAT_HISTORIES[session_id].append({"role": "assistant", "content": response})
                
                # Persist to database
                persist_chat_message(session_id, "user", query)
                persist_chat_message(session_id, "assistant", response, metadata={
                    "llm_used": True,
                    "rag_used": False,  # RAG not used in non-streaming endpoint
                    "confidence": 0.9,  # Default confidence
                    "response_time": calculate_response_time(),
                    "model_used": LLM_MODEL
                })
                
                return jsonify({
                    "status": "SUCCESS",
                    "response": response,
                    "confidence": 0.9,
                    "response_time": calculate_response_time(),
                    "model_used": "Qwen2.5-VL-7B",
                    "multimodal": True
                })
            elif error:
                logger.warning(f"Qwen2.5-VL processing failed: {error}, falling back to LLM")
        
        # All queries now go through LLM processing - no hardcoded responses

        # Always try LLM first for better conversational responses
        logger.debug(f"USE_LLM = {USE_LLM} (type: {type(USE_LLM)})")
        if USE_LLM:
            logger.info("LLM integration enabled, processing with AI Chat Assistant")
            # Initialize session if needed for conversation memory (do this early)
            if 'session_id' not in session:
                import uuid
                session['session_id'] = str(uuid.uuid4())
                CHAT_HISTORIES[session['session_id']] = []
            
            session_id = session['session_id']
            
            try:
                # Quick check if LM Studio is running
                logger.info("Checking LM Studio health...")
                try:
                    health_check = requests.get("http://localhost:1234/v1/models", timeout=5)
                    if not health_check.ok:
                        logger.error(f"LM Studio health check failed: HTTP {health_check.status_code}")
                        raise Exception(f"LM Studio health check failed: HTTP {health_check.status_code}")
                    logger.info("LM Studio health check passed")
                except requests.exceptions.Timeout:
                    logger.error("LM Studio health check timed out after 5 seconds")
                    raise Exception("LM Studio health check timed out. LM Studio may be slow or unresponsive.")
                except requests.exceptions.ConnectionError as e:
                    logger.error(f"Cannot connect to LM Studio: {str(e)}")
                    raise Exception(f"Cannot connect to LM Studio at http://localhost:1234. Is LM Studio server running?")
                
                # Get chat history for this session
                chat_history = CHAT_HISTORIES.get(session_id, [])
                logger.debug(f"Chat history: {len(chat_history)} messages in session")
                
                # Get enhanced data context for LLM with actual details
                data_context = ""
                image_citations = []
                if data_src:
                    logger.info(f"Extracting data from {len(data_src)} file(s)...")
                    
                    # CRITICAL: Check if this is a summary/overview question
                    is_summary_query = is_query_too_broad(query)
                    
                    if is_summary_query:
                        # Generate pre-summarized overview instead of raw data dump
                        logger.info("📊 Summary query detected - generating forensic overview instead of raw data")
                        overview = generate_forensic_overview(data_src)
                        
                        # Format as structured data for LLM
                        data_context = f"""FORENSIC OVERVIEW (AUTHORITATIVE):
- Contacts: {overview['contacts_count']}
- Messages: {overview['messages_count']}
- Calls: {overview['calls_count']}
- Locations: {overview['locations_count']}
- Date Range: {overview['date_range'] or 'Not available'}
- Platforms: {', '.join(overview['top_apps']) if overview['top_apps'] else 'Not available'}
- Most Active Contacts: {', '.join(overview['most_active_contacts']) if overview['most_active_contacts'] else 'Not available'}"""
                        
                        logger.info(f"✅ Generated forensic overview: {overview}")
                    else:
                        # NEW: Option to let LLM extract directly from JSON
                        if use_json_extraction:
                            logger.info("Using JSON extraction mode - LLM will extract data directly from JSON")
                            for filename, data in data_src.items():
                                # Skip metadata keys like '_zip_info' - only process actual UFDR data
                                if filename.startswith('_'):
                                    continue
                                
                                if isinstance(data, dict):
                                    try:
                                        logger.debug(f"Preparing JSON for LLM from file: {filename}")
                                        # Ensure query is safe for prepare_json_for_llm
                                        safe_query = query if query and isinstance(query, str) else ""
                                        json_context = prepare_json_for_llm(data, safe_query, max_chars=500000)
                                        if data_context:
                                            data_context += "\n\n--- Additional Data ---\n\n"
                                        data_context += json_context
                                    except Exception as e:
                                        logger.warning(f"Error preparing JSON for LLM: {e}, falling back to text extraction")
                                        # Fallback to semantic extraction (Magnet AXIOM style)
                                        safe_query = query if query and isinstance(query, str) else ""
                                        try:
                                            extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                            # Truncate to fit context window
                                            extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                            logger.info(f"🔍 Semantic extraction (fallback): {len(extracted_context)} characters")
                                        except Exception as e:
                                            logger.warning(f"Semantic extraction failed: {e}, using enhanced extractor")
                                            extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                            # Truncate to fit context window
                                            extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        data_context = extracted_context
                                        logger.debug(f"Extracted context length: {len(data_context)} characters")
                                    logger.debug(f"JSON context length: {len(json_context)} characters")
                        else:
                            # Original approach: Use enhanced extractor to get specific UFDR details
                            for filename, data in data_src.items():
                                # Skip metadata keys like '_zip_info' - only process actual UFDR data
                                if filename.startswith('_'):
                                    continue
                                
                                if isinstance(data, dict):
                                    logger.debug(f"Processing file: {filename}")
                                    # Ensure query is safe
                                    safe_query = query if query and isinstance(query, str) else ""
                                    # Use semantic extractor (Magnet AXIOM style) - extracts ALL relevant data
                                    try:
                                        extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"🔍 Semantic extraction: {len(extracted_context)} characters")
                                    except Exception as e:
                                        logger.warning(f"Semantic extraction failed: {e}, falling back to enhanced extractor")
                                        extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"📊 Fallback extraction: {len(extracted_context)} characters")
                                    data_context = extracted_context
                                    logger.debug(f"Extracted context length: {len(data_context)} characters")
                                
                                # Extract image citations
                                try:
                                    if query and isinstance(query, str):  # Safety check
                                        image_citations = image_citation_extractor.extract_image_citations(data, query)
                                        if image_citations:
                                            logger.info(f"Found {len(image_citations)} relevant image citations")
                                            # Add image info to context if it's an image query
                                            if image_citation_extractor.is_image_query(query):
                                                image_info = image_citation_extractor.format_image_citations(image_citations)
                                                data_context += image_info
                                except Exception as e:
                                    logger.warning(f"Error extracting image citations: {e}")
                                
                                break  # Use first file for now
                else:
                    logger.warning("No data source available")
                
                # Detect query language and add language instruction
                from utils.language_detector import detect_language, get_language_instruction
                detected_language = detect_language(query)
                language_instruction = get_language_instruction(detected_language)
                
                # Prepare messages for LM Studio (OpenAI-compatible format)
                messages = []
                
                messages.append({
                    "role": "system",
                    "content": f"""You are an elite digital forensics analyst with expertise in mobile device forensics, communication analysis, and evidence investigation. Your role is to conduct thorough, professional forensic examinations of UFDR (Universal Forensic Data Report) files.

🌐 LANGUAGE REQUIREMENT: {language_instruction}
You MUST respond in the same language as the user's query. Match the user's language exactly.

⚠️ CRITICAL: ALWAYS answer the user's specific question directly. Your entire response must focus on what the user asked. Do not provide generic analysis that doesn't address the specific query.

CORE CAPABILITIES:
- Deep analysis of messages (SMS, WhatsApp, iMessage), call logs, contacts, and device metadata
- Timeline reconstruction and chronological event analysis
- Relationship mapping between contacts, communications, and activities
- Pattern recognition for suspicious behaviors, security threats, and anomalies
- Evidence correlation and cross-referencing across multiple data sources
- Chain of custody documentation and evidence integrity verification

ANALYSIS METHODOLOGY:
1. QUERY FOCUS: First, identify the user's specific question and ensure your entire response addresses it
2. EVIDENCE IDENTIFICATION: Identify all relevant evidence related to the user's query
3. CONTEXTUAL ANALYSIS: Examine evidence within temporal, relational, and behavioral context
4. PATTERN DETECTION: Identify communication patterns, frequency anomalies, timing patterns
5. CORRELATION: Connect related evidence across different data types (messages↔calls↔contacts)
6. RISK ASSESSMENT: Evaluate security concerns, suspicious activities, and potential threats
7. ACTIONABLE INTELLIGENCE: Provide specific, actionable findings with evidence citations

RESPONSE REQUIREMENTS:
- ALWAYS answer the user's specific question - do not provide unrelated information
- Always cite specific evidence (dates, timestamps, contact names, message content, call durations)
- Include timestamps and temporal context for all findings
- Use professional forensic terminology (e.g., "artifact", "evidence", "chain of custody", "metadata")
- Maintain objectivity - distinguish between facts and inferences
- Provide confidence levels when making inferences
- Structure responses with clear sections for different types of analysis
- If the user asks about specific people or relationships, focus ONLY on those people/relationships

Your goal is to provide comprehensive, professional forensic analysis that directly answers the user's question and would stand up in a legal or investigative context."""
                })
                
                # Add conversation history if available (for follow-up questions)
                # NO LIMIT - Include all chat history (excluding current query which was just added)
                if session_id in CHAT_HISTORIES and CHAT_HISTORIES[session_id]:
                    # Get all history except the last message (which is the current query we just added)
                    history_messages = CHAT_HISTORIES[session_id][:-1] if len(CHAT_HISTORIES[session_id]) > 1 else []
                    logger.debug(f"Including {len(history_messages)} previous messages for context (no limit)")
                    for msg in history_messages:
                        # Ensure role is valid (user or assistant)
                        role = msg.get("role", "user")
                        if role not in ["user", "assistant"]:
                            role = "user" if role == "user" else "assistant"
                        # NO TRUNCATION - Send full chat history
                        content = msg.get("content", "")
                        if content:  # Only add non-empty messages
                            messages.append({
                                "role": role,
                                "content": content
                            })
                else:
                    logger.debug("No previous conversation history")
                
                # Add current query with forensic data
                # (The query is already in CHAT_HISTORIES, but we add it here with data context)
                if data_context:
                    # Dynamic context-aware truncation
                    # Calculate actual available space based on system message, query, and response buffer
                    # Model has LLM_CONTEXT_LENGTH tokens total
                    
                    # Estimate system message size (first message)
                    system_chars = len(messages[0].get('content', '')) if messages else 0
                    system_tokens = int(system_chars / 1.67)
                    
                    # Estimate query size
                    query_chars = len(query)
                    query_tokens = int(query_chars / 1.67)
                    
                    # Reserve tokens for response (minimum 200 tokens for response)
                    response_reserve = 200
                    
                    # Calculate available space for data
                    # Total: LLM_CONTEXT_LENGTH tokens
                    # Used: system + query + response buffer
                    # Available: LLM_CONTEXT_LENGTH - system - query - response
                    available_tokens = LLM_CONTEXT_LENGTH - system_tokens - query_tokens - response_reserve
                    
                    # Add some safety margin (reduce by 10% to be safe)
                    available_tokens = int(available_tokens * 0.9)
                    
                    # Ensure minimum available space (at least 500 tokens)
                    available_tokens = max(500, available_tokens)
                    
                    logger.info(f"📊 Context calculation: System={system_tokens} tokens, Query={query_tokens} tokens, Available for data={available_tokens} tokens (out of {LLM_CONTEXT_LENGTH} total)")
                    
                    # Truncate data_context to fit available space
                    # Convert tokens to characters (1 token ≈ 1.67 characters)
                    available_chars = int(available_tokens * 1.67)
                    
                    if len(data_context) > available_chars:
                        logger.warning(f"⚠️ Truncating data from {len(data_context)} to {available_chars} characters to fit {LLM_CONTEXT_LENGTH} token context")
                        # Use truncate_for_context with calculated available space
                        data_context = truncate_for_context(data_context, max_tokens=LLM_CONTEXT_LENGTH, reserved_tokens=(LLM_CONTEXT_LENGTH - available_tokens))
                    else:
                        logger.info(f"✅ Data fits within context: {len(data_context)} characters")
                    
                    user_message = f"{query}\n\nFORENSIC DATA:\n{data_context}"
                else:
                    user_message = query
                messages.append({
                    "role": "user",
                    "content": user_message
                })
                
                logger.info(f"Using model: {LLM_MODEL}")
                logger.debug(f"Prompt length: {len(prompt)} characters")
                logger.debug(f"Sending request to LM Studio at {LLM_URL}...")
                
                import time
                llm_start = time.time()
                # LM Studio uses OpenAI-compatible API format
                # CRITICAL: 3B models MUST be cold and short for forensic work
                resp = requests.post(
                    LLM_URL,
                    json={
                        "model": LLM_MODEL,
                        "messages": messages,
                        "temperature": 0.2,  # Lower temperature for more deterministic, less hallucination
                        "max_tokens": 1200,  # Shorter responses prevent fabrication
                        "stream": False
                    },
                    timeout=90
                )
                llm_time = time.time() - llm_start
                logger.info(f"LM Studio responded in {llm_time:.2f} seconds with status {resp.status_code}")
                
                if resp.ok:
                    try:
                        response_data = resp.json()
                        
                        # Check for error responses from LM Studio
                        if 'error' in response_data:
                            error_info = response_data.get('error', {})
                            error_message = error_info.get('message', 'Unknown error from LM Studio')
                            logger.error(f"❌ LM Studio returned an error: {error_message}")
                            
                            # Check if it's a context length error
                            if 'context' in error_message.lower() or 'token' in error_message.lower() or str(LLM_CONTEXT_LENGTH) in error_message:
                                error_msg = f"""⚠️ **CONTEXT LENGTH EXCEEDED**

The prompt is too long for the model's context window.

**Error Details:**
{error_message}

**Problem:**
- Your model in LM Studio is loaded with a context length of **{LLM_CONTEXT_LENGTH} tokens**
- The current prompt requires approximately **{int(sum(len(msg.get('content', '')) for msg in messages) / 1.67)} tokens**
- This exceeds the model's capacity

**Solutions:**

1. **Increase Model Context Length (Recommended):**
   - In LM Studio, go to the model settings
   - Increase the "Context Length" to at least **{LLM_CONTEXT_LENGTH * 2}** or **{LLM_CONTEXT_LENGTH * 4}** tokens
   - Reload the model with the new context length
   - Or set environment variable: `LLM_CONTEXT_LENGTH={LLM_CONTEXT_LENGTH * 2}` and restart the server

2. **Use a Model with Larger Context:**
   - Switch to a model that supports larger contexts (e.g., Qwen2.5-7B-Instruct with 32K context)
   - Or use a model specifically designed for longer contexts

3. **Reduce Data Size:**
   - Try a more specific query that requires less data
   - The system will automatically truncate data, but very large cases may still exceed limits

**Current Prompt Size:** {sum(len(msg.get('content', '')) for msg in messages)} characters (~{int(sum(len(msg.get('content', '')) for msg in messages) / 1.67)} tokens)"""
                            else:
                                error_msg = f"""⚠️ **LM STUDIO ERROR**

The LLM server returned an error:

**Error:** {error_message}

**Troubleshooting:**
1. Check if LM Studio is running and the model is loaded
2. Verify the model is compatible with the API
3. Check LM Studio logs for more details
4. Try restarting LM Studio server"""
                            
                            return jsonify({
                                "status": "ERROR",
                                "message": "LM Studio error",
                                "error_type": "LLM_ERROR",
                                "error_details": {
                                    "error_message": error_message,
                                    "user_message": error_msg
                                }
                            })
                        
                        # LM Studio returns OpenAI format: choices[0].message.content
                        llm_response = response_data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
                        
                        if not llm_response:
                            logger.warning(f"Empty response from LM Studio. Full response: {response_data}")
                            raise Exception("LM Studio returned empty response")
                        
                        # User query was already added to CHAT_HISTORIES before sending to LLM
                        # Now add the assistant response
                        # Ensure session history exists
                        if session_id not in CHAT_HISTORIES:
                            CHAT_HISTORIES[session_id] = []
                        
                        CHAT_HISTORIES[session_id].append({
                            "role": "assistant",
                            "content": llm_response,
                            "timestamp": datetime.now().isoformat()
                        })
                        
                        # Persist to database
                        # NO LIMIT - Keep all chat history
                        # Removed limit to allow full conversation context
                        
                        # Calculate confidence for LLM response
                        intent_strength = confidence_calculator.calculate_intent_strength(query, "llm_query")
                        query_complexity = confidence_calculator.calculate_query_complexity(query)
                        confidence = confidence_calculator.calculate_confidence(
                            retrieval_scores=[0.9],  # High confidence for LLM responses
                            intent_strength=intent_strength,
                            data_completeness=1.0,
                            query_complexity=query_complexity,
                            response_quality=0.95  # High quality LLM response
                        )
                        
                        # Persist to database (after confidence is calculated)
                        persist_chat_message(session_id, "user", query)
                        persist_chat_message(session_id, "assistant", llm_response, metadata={
                            "llm_used": True,
                            "rag_used": False,  # RAG not used in this endpoint
                            "confidence": confidence,
                            "response_time": calculate_response_time(),
                            "model_used": LLM_MODEL
                        })
                        
                        logger.info("LLM response received successfully")
                        
                        # Prepare image citations for response (only include essential fields)
                        image_citations_response = []
                        for citation in image_citations:
                            image_citations_response.append({
                                "filename": citation.get("filename", ""),
                                "relative_path": citation.get("relative_path", ""),
                                "path": citation.get("path", ""),
                                "context": citation.get("context", ""),
                                "relevance_score": citation.get("relevance_score", 0)
                            })
                        
                        # Check if query is asking for suspicious contacts/data - if so, also search the data
                        query_lower = query.lower() if query else ""
                        data_matches = []
                        has_detailed_results = False
                        detailed_summary = "LLM-generated response"
                        
                        # Detect queries asking for suspicious contacts/data
                        is_suspicious_query = any(phrase in query_lower for phrase in [
                            'suspicious contact', 'list suspicious', 'show suspicious', 'find suspicious', 
                            'suspicious contacts', 'suspicious data', 'suspicious activity', 'suspicious pattern'
                        ])
                        
                        if is_suspicious_query:
                            logger.info("🔍 Query asks for suspicious contacts/data - performing data search...")
                            try:
                                # Import suspicious keywords
                                try:
                                    from engines.nl_query_engine import SUSPICIOUS_GENERIC_KEYWORDS, SUSPICIOUS_MONEY_KEYWORDS
                                except ImportError:
                                    # Fallback suspicious keywords if import fails
                                    SUSPICIOUS_GENERIC_KEYWORDS = [
                                        "send package", "otp", "one time password", "pin", "password",
                                        "confidential", "credential", "delete", "erase"
                                    ]
                                    SUSPICIOUS_MONEY_KEYWORDS = [
                                        "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
                                        "UPI", "bank", "account", "deposit", "withdraw", "wallet"
                                    ]
                                
                                all_suspicious_keywords = SUSPICIOUS_GENERIC_KEYWORDS + SUSPICIOUS_MONEY_KEYWORDS
                                
                                # Use enhanced NL engine to search for suspicious contacts
                                if enhanced_nl_engine and data_src:
                                    # Search for suspicious contacts
                                    suspicious_contacts = []
                                    suspicious_messages = []
                                    contacts_dict = {}
                                    
                                    for filename, data in data_src.items():
                                        if filename.startswith('_'):
                                            continue
                                        
                                        # Build contacts dictionary
                                        for contact in data.get('contacts', []):
                                            phone = contact.get('phone', '')
                                            name = contact.get('name', '')
                                            if phone and phone not in contacts_dict:
                                                contacts_dict[phone] = {
                                                    'name': name or 'Unknown',
                                                    'phone': phone,
                                                    'email': contact.get('email', ''),
                                                    'suspicious_count': 0,
                                                    'suspicious_messages': [],
                                                    'source_file': filename
                                                }
                                        
                                        # Check messages for suspicious keywords
                                        for msg in data.get('messages', []):
                                            text = (msg.get('text') or msg.get('content') or '').lower()
                                            if any(kw in text for kw in all_suspicious_keywords):
                                                from_phone = msg.get('from') or msg.get('sender', '')
                                                to_phone = msg.get('to') or msg.get('receiver', '')
                                                
                                                # Track suspicious activity for contacts
                                                if from_phone in contacts_dict:
                                                    contacts_dict[from_phone]['suspicious_count'] += 1
                                                    contacts_dict[from_phone]['suspicious_messages'].append({
                                                        'timestamp': msg.get('timestamp'),
                                                        'text': msg.get('text') or msg.get('content', ''),
                                                        'to': to_phone
                                                    })
                                                
                                                if to_phone and to_phone in contacts_dict:
                                                    contacts_dict[to_phone]['suspicious_count'] += 1
                                                    contacts_dict[to_phone]['suspicious_messages'].append({
                                                        'timestamp': msg.get('timestamp'),
                                                        'text': msg.get('text') or msg.get('content', ''),
                                                        'from': from_phone
                                                    })
                                                
                                                suspicious_messages.append({
                                                    'type': 'message',
                                                    'timestamp': msg.get('timestamp'),
                                                    'from': from_phone,
                                                    'to': to_phone,
                                                    'text': msg.get('text') or msg.get('content', ''),
                                                    'source_file': filename
                                                })
                                        
                                        # Also check for contacts with suspicious names/emails
                                        for contact in data.get('contacts', []):
                                            phone = contact.get('phone', '')
                                            name = (contact.get('name') or '').lower()
                                            email = (contact.get('email') or '').lower()
                                            
                                            # Check if contact name/email looks suspicious
                                            suspicious_name_keywords = ['unknown', 'external', 'temp', 'suspicious', 'blocked']
                                            if any(kw in name for kw in suspicious_name_keywords) or any(kw in email for kw in suspicious_name_keywords):
                                                if phone not in contacts_dict:
                                                    contacts_dict[phone] = {
                                                        'name': contact.get('name', 'Unknown'),
                                                        'phone': phone,
                                                        'email': contact.get('email', ''),
                                                        'suspicious_count': 1,
                                                        'suspicious_messages': [],
                                                        'source_file': filename
                                                    }
                                    
                                    # Add contacts with suspicious activity
                                    for phone, contact_info in contacts_dict.items():
                                        if contact_info['suspicious_count'] > 0:
                                            suspicious_contacts.append({
                                                'type': 'contact',
                                                'name': contact_info['name'],
                                                'phone': phone,
                                                'email': contact_info.get('email', ''),
                                                'suspicious_count': contact_info['suspicious_count'],
                                                'source_file': contact_info.get('source_file', filename)
                                            })
                                    
                                    # Combine contacts and messages
                                    data_matches = suspicious_contacts + suspicious_messages
                                    
                                    if data_matches:
                                        has_detailed_results = True
                                        detailed_summary = f"Found {len(suspicious_contacts)} suspicious contact(s) with {len(suspicious_messages)} suspicious message(s)"
                                        logger.info(f"✅ Found {len(suspicious_contacts)} suspicious contacts and {len(suspicious_messages)} suspicious messages")
                                    else:
                                        logger.info("ℹ️ No suspicious contacts found in data")
                                        
                            except Exception as e:
                                logger.warning(f"Error searching for suspicious contacts: {e}", exc_info=True)
                                # Continue with LLM response even if data search fails
                        
                        # Use LLM response as-is
                        final_response = llm_response
                        
                        return jsonify({
                            "status": "SUCCESS",
                            "query": query,
                            "response": final_response,
                            "confidence": confidence,
                            "llm_used": True,
                            "rag_used": False,
                            "has_detailed_results": has_detailed_results,
                            "image_citations": image_citations_response,  # Add image citations
                            "has_images": len(image_citations_response) > 0,
                            "detailed_results": {
                                "matches": data_matches,
                                "data_sources": list(data_src.keys()),
                                "semantic_mappings": {},
                                "summary": detailed_summary,
                                "recommendations": ["Ask follow-up questions for more specific analysis"] if not data_matches else [],
                                "total_matches": len(data_matches)
                            },
                            "response_time": calculate_response_time()
                        })
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse LM Studio response: {e}")
                        logger.debug(f"Response status: {resp.status_code}")
                        logger.debug(f"Response text (first 500 chars): {resp.text[:500]}")
                        raise Exception(f"Invalid response from LM Studio: {str(e)}")
                else:
                    logger.error(f"LM Studio API error: Status {resp.status_code}")
                    logger.debug(f"Response: {resp.text[:500]}")
                    raise Exception(f"LM Studio API returned error: HTTP {resp.status_code}")
            except requests.exceptions.Timeout as e:
                error_msg = "Request to LM Studio timed out after 90 seconds."
                print(f"LLM Timeout Error: {error_msg}")
                print(f"Timeout details: {str(e)}")
                return jsonify({
                    "status": "ERROR",
                    "message": "LLM request timed out",
                    "error_type": "TIMEOUT",
                    "error_details": {
                        "reason": "LM Studio took too long to respond (90+ seconds)",
                        "possible_causes": [
                            "Model is processing very large context",
                            "LM Studio is overloaded or slow",
                            "System resources are limited"
                        ],
                        "solutions": [
                            "Try a simpler query",
                            "Restart LM Studio server",
                            "Check system resources (CPU/RAM/GPU)",
                            "Try reducing the UFDR file size"
                        ],
                        "timeout_seconds": 90,
                        "response_time": calculate_response_time()
                    },
                    "response": f"⏱️ **TIMEOUT ERROR**\n\nThe request to LM Studio timed out after 90 seconds. This usually means:\n\n• The model is processing a very large context\n• LM Studio is slow or overloaded\n• Your system needs more resources\n\n**Try:**\n1. Restart LM Studio server\n2. Use a simpler query\n3. Check system resources (GPU/CPU/RAM)",
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })
            except requests.exceptions.ConnectionError as e:
                error_msg = f"Cannot connect to LM Studio at {LLM_URL}"
                print(f"LLM Connection Error: {error_msg}")
                print(f"Connection error details: {str(e)}")
                
                # Try to diagnose the issue
                diagnostic_info = {
                    "reason": "Cannot establish connection to LM Studio",
                    "lm_studio_url": LLM_URL,
                    "possible_causes": [
                        "LM Studio server is not running",
                        "LM Studio is running on a different port",
                        "Firewall is blocking the connection"
                    ],
                    "solutions": [
                        "Start LM Studio: Open LM Studio app, go to 'Local Server' tab, and click 'Start Server'",
                        "Check if LM Studio server is running: Visit http://localhost:1234 in your browser",
                        "Verify LM Studio is on port 1234: Check the 'Local Server' tab in LM Studio"
                    ]
                }
                
                return jsonify({
                    "status": "ERROR",
                    "message": "Cannot connect to LM Studio",
                    "error_type": "CONNECTION_ERROR",
                    "error_details": diagnostic_info,
                    "response": f"🔌 **CONNECTION ERROR**\n\nCannot connect to LM Studio at {LLM_URL}\n\n**Most likely cause:** LM Studio server is not running\n\n**Quick fix:**\n1. Open LM Studio application\n2. Go to 'Local Server' tab\n3. Click 'Start Server'\n4. Verify: Check that server is running on port 1234\n\n**Check:** Make sure the model is loaded in LM Studio",
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                print(f"LLM Error ({error_type}): {error_msg}")
                import traceback
                full_traceback = traceback.format_exc()
                print("Full traceback:")
                print(full_traceback)
                
                # Don't expose session IDs or internal details in error message
                if len(error_msg) == 36 and '-' in error_msg:  # Looks like a UUID
                    error_msg = "Internal session error"
                
                # Create user-friendly error message
                user_message = f"❌ **ERROR: {error_type}**\n\n{error_msg}\n\n**What happened:**\nAn unexpected error occurred while processing your request.\n\n**Check:**\n• Flask server console for detailed error logs\n• LM Studio server is running and accessible\n• The UFDR file is properly loaded"
                
                return jsonify({
                    "status": "ERROR",
                    "message": error_msg,
                    "error_type": error_type,
                    "error_details": {
                        "reason": error_msg,
                        "full_error": full_traceback[-500:] if len(full_traceback) > 500 else full_traceback,  # Last 500 chars
                        "solutions": [
                            "Check Flask server console for full error details",
                            "Verify LM Studio server is running: Check LM Studio 'Local Server' tab",
                            "Try restarting both Flask and LM Studio server",
                            "Check if the UFDR file is valid"
                        ]
                    },
                    "response": user_message,
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })

        # If LLM is disabled, return an error message
        print(f"❌ ERROR: USE_LLM is {USE_LLM}, LLM block was not entered!")
        print(f"   USE_LLM type: {type(USE_LLM)}, value: {repr(USE_LLM)}")
        return jsonify({
            "status": "ERROR",
            "message": "LLM service unavailable",
            "error_type": "LLM_DISABLED",
            "error_details": {
                "reason": f"USE_LLM is set to {USE_LLM} (expected True)",
                "actual_value": str(USE_LLM),
                "solution": "Enable LLM in web_interface.py by setting USE_LLM = True, then RESTART the Flask server"
            },
            "response": f"🚨 **LLM_DISABLED**\n\nThe LLM is currently disabled.\n\n**Current setting:** USE_LLM = {USE_LLM}\n\n**Fix:**\n1. Open `FORENSIC/web_interface.py`\n2. Find line 55 and ensure it says: `USE_LLM = True`\n3. **RESTART your Flask server** (Ctrl+C, then start again)\n4. Try again",
            "confidence": 0.0,
            "llm_used": False,
            "rag_used": False,
            "response_time": calculate_response_time()
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error in chat query: {str(e)}",
            "response": f"I apologize, but I encountered an error while analyzing your forensic query. Please try rephrasing your question or check if the data is properly loaded.",
            "confidence": 0.0,
            "response_time": calculate_response_time()
        })

def generate_chat_response(result, query):
    """Generate a forensic investigator-style conversational response from AI retrieval results."""
    # Safety check for None query
    if not query:
        return "I need a question to investigate. What would you like me to analyze?"
    
    # Friendly greeting for casual messages
    if query and isinstance(query, str) and query.strip().lower() in {"hi", "hello", "hey", "hey there"}:
        return "Hello! I'm your forensic AI assistant. Upload a UFDR JSON file or ask me to investigate specific patterns in your forensic data (e.g., 'Find suspicious calls', 'Analyze message patterns', 'Who are the top contacts')."
    
    if result.confidence == 0 or not result.matches:
        return (
            f"After thorough analysis, I couldn't find specific evidence related to '{query}' in the forensic data. "
            "Try searching for more specific terms like phone numbers, names, or keywords such as 'OTP', 'payment', or 'suspicious activity'."
        )
    
    # Determine response type based on query
    query_lower = query.lower() if query else ""
    
    if query_lower and any(word in query_lower for word in ['owner', 'who', 'belongs', 'user']):
        return generate_owner_response(result)
    elif any(word in query_lower for word in ['device', 'phone', 'model', 'imei']):
        return generate_device_response(result)
    elif any(word in query_lower for word in ['contact', 'call', 'message', 'communication']):
        return generate_communication_response(result)
    elif any(word in query_lower for word in ['suspicious', 'fraud', 'scam', 'threat']):
        return generate_security_response(result)
    else:
        return generate_general_response(result)

def generate_owner_response(result):
    """Generate owner-specific response."""
    if result.matches:
        match = result.matches[0]
        if match['source'] == 'contacts':
            return f"Based on the contacts, the device likely belongs to **{match['data'].get('name', 'Unknown')}**. I found this information with {result.confidence}% confidence."
        elif match['source'] == 'device_info':
            return f"From device metadata, I found registration information suggesting the owner. Confidence: {result.confidence}%."
    return f"I found some potential owner information with {result.confidence}% confidence. Check the detailed results for more specifics."

def generate_device_response(result):
    """Generate device-specific response."""
    if result.matches:
        match = result.matches[0]
        data = match.get('data', {})
        if isinstance(data, dict):
            model = data.get('model', data.get('device_model', 'Unknown'))
            return f"This appears to be a **{model}** device. I found this information with {result.confidence}% confidence."
    return f"I found device information with {result.confidence}% confidence. Check detailed results for specifications."

def generate_communication_response(result):
    """Generate communication-specific response."""
    total_matches = len(result.matches)
    if total_matches > 0:
        return f"I found **{total_matches}** communication records related to your query. The most relevant results show {result.summary if result.summary else 'various communication patterns'}."
    return f"Found {total_matches} communication records with {result.confidence}% confidence."

def generate_security_response(result):
    """Generate security/threat-specific response."""
    if result.matches:
        return f"⚠️ I found **{len(result.matches)}** potentially suspicious items. This requires immediate attention. Confidence: {result.confidence}%."
    return f"Security analysis complete. Found {len(result.matches)} items of interest with {result.confidence}% confidence."

def generate_general_response(result):
    """Generate general response."""
    total_matches = len(result.matches)
    if total_matches > 0:
        return f"I found **{total_matches}** relevant results for your query. {result.summary if result.summary else 'The information includes various data points from the device.'} Confidence: {result.confidence}%."
    return f"Found {total_matches} results with {result.confidence}% confidence."

@app.route('/api/quick-commands')
def get_quick_commands():
    """Get quick command categories and examples."""
    quick_commands = {
        "Common Queries": {
            "icon": "fas fa-search",
            "color": "success",
            "commands": [
                "Show me all contacts",
                "Find messages about money",
                "Show calls from last week",
                "Find suspicious activities",
                "Show device information"
            ]
        },
        "Analysis Queries": {
            "icon": "fas fa-chart-line",
            "color": "warning", 
            "commands": [
                "Analyze communication patterns",
                "Find financial transactions",
                "Show relationship networks",
                "Identify threat indicators"
            ]
        },
        "Evidence Queries": {
            "icon": "fas fa-file-alt",
            "color": "primary",
            "commands": [
                "Show deleted messages",
                "Find encrypted communications",
                "Show media files",
                "Find location data"
            ]
        }
    }
    return jsonify(quick_commands)

@app.route('/api/rag-reindex', methods=['POST'])
def rag_reindex():
    """Rebuild RAG index from current data (uploads or synthetic)."""
    try:
        if rag_engine is None:
            return jsonify({"status": "DISABLED", "message": "RAG engine is disabled", "ready": False})
        rebuild_rag_index()
        return jsonify({"status": "SUCCESS", "ready": rag_engine.is_ready()})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/rag-answer', methods=['POST'])
def rag_answer():
    """Answer NL question using retrieval-augmented generation over UFDR data."""
    try:
        if rag_engine is None:
            return jsonify({
                "status": "DISABLED",
                "message": "RAG engine is disabled - using keyword-based extraction",
                "ready": False,
                "summary": "RAG is disabled. The system will use keyword-based extraction instead.",
                "matches": [],
                "used_rag": False
            })
        data = request.get_json() or {}
        question = (data.get('query') or data.get('message') or '').strip()
        k = int(data.get('k', 10))
        if not question:
            return jsonify({"status": "ERROR", "message": "No query provided"})
        # Ensure uploads present
        if not get_current_data():
            return jsonify({"status": "ERROR", "message": "Upload a UFDR JSON file first."})
        # Ensure index exists
        if not rag_engine.is_ready():
            rebuild_rag_index()
        rag_result = rag_engine.query(question, k)
        return jsonify({
            "status": "SUCCESS",
            "ready": rag_result.get('ready', False),
            "summary": rag_result.get('summary', ''),
            "matches": rag_result.get('matches', []),
            "used_rag": rag_result.get('used_rag', False)
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/smart-analysis', methods=['POST'])
def smart_analysis():
    """Perform intelligent analysis of uploaded UFDR data."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Perform smart analysis
        analysis_results = smart_analyzer.analyze_data(data_src)
        
        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis_results
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error performing smart analysis: {str(e)}"
        })

@app.route('/api/explore-data', methods=['GET'])
def explore_data():
    """Get all raw data (messages, contacts, calls) for exploration."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Prepare exploration data
        exploration_data = {
            "contacts": [],
            "messages": [],
            "calls": [],
            "files": []
        }
        
        # Build contact lookup map: phone -> name
        contact_map = {}  # phone number -> contact name
        
        # First pass: collect all contacts and build lookup map
        for filename, file_data in data_src.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        # Collect contacts and build lookup map
                        for contact in device.get("contacts", []):
                            if isinstance(contact, dict):
                                name = contact.get("name", "").strip()
                                phone = contact.get("phone", contact.get("number", "")).strip()
                                
                                if phone:
                                    # Store contact
                                    exploration_data["contacts"].append({
                                        "name": name or "Unknown",
                                        "phone": phone,
                                        "email": contact.get("email", ""),
                                        "source_file": filename
                                    })
                                    
                                    # Add to lookup map (multiple formats) if we have a name
                                    if name and name != "Unknown" and name:
                                        # Normalize phone number (remove spaces, dashes, etc.)
                                        normalized_phone = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
                                        
                                        contact_map[phone] = name
                                        contact_map[normalized_phone] = name
                                        # Also try with + prefix
                                        if not phone.startswith("+"):
                                            contact_map["+" + phone] = name
                                            contact_map["+" + normalized_phone] = name
                                        else:
                                            contact_map[phone[1:]] = name  # Without +
        
        # Helper function to resolve phone to name
        def resolve_contact(phone_or_name):
            """Resolve phone number or name to contact name."""
            if not phone_or_name or phone_or_name == "Unknown":
                return "Unknown"
            
            # If it's already a name (not a phone number), return as is
            # Check if it contains digits (likely a phone number)
            digits_only = ''.join(c for c in phone_or_name if c.isdigit())
            if len(digits_only) < 7:  # Less than 7 digits, probably not a phone number
                return phone_or_name
            
            # Try to find in contact map
            normalized = phone_or_name.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
            
            # Try exact match
            if phone_or_name in contact_map:
                return contact_map[phone_or_name]
            if normalized in contact_map:
                return contact_map[normalized]
            
            # Try with/without + prefix
            if phone_or_name.startswith("+"):
                without_plus = phone_or_name[1:]
                if without_plus in contact_map:
                    return contact_map[without_plus]
                # Try normalized without +
                normalized_without_plus = normalized[1:] if normalized.startswith("+") else normalized
                if normalized_without_plus in contact_map:
                    return contact_map[normalized_without_plus]
            else:
                with_plus = "+" + phone_or_name
                if with_plus in contact_map:
                    return contact_map[with_plus]
                # Try normalized with +
                normalized_with_plus = "+" + normalized
                if normalized_with_plus in contact_map:
                    return contact_map[normalized_with_plus]
            
            # Not found in contacts
            return "Unknown"
        
        # Second pass: collect messages and calls with resolved names
        for filename, file_data in data_src.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        
                        # Collect messages with resolved contact names
                        for message in device.get("messages", []):
                            if isinstance(message, dict):
                                from_val = message.get("from", message.get("sender", "Unknown"))
                                to_val = message.get("to", message.get("receiver", "Unknown"))
                                
                                from_name = resolve_contact(from_val)
                                to_name = resolve_contact(to_val)
                                
                                exploration_data["messages"].append({
                                    "text": message.get("text", "") or message.get("content", ""),
                                    "from": from_val,
                                    "from_name": from_name,
                                    "to": to_val,
                                    "to_name": to_name,
                                    "timestamp": message.get("timestamp", ""),
                                    "source_file": filename
                                })
                        
                        # Collect calls with resolved contact names
                        for call in device.get("call_logs", device.get("calls", [])):
                            if isinstance(call, dict):
                                from_val = call.get("from", call.get("caller", "Unknown"))
                                to_val = call.get("to", call.get("receiver", "Unknown"))
                                
                                from_name = resolve_contact(from_val)
                                to_name = resolve_contact(to_val)
                                
                                exploration_data["calls"].append({
                                    "from": from_val,
                                    "from_name": from_name,
                                    "to": to_val,
                                    "to_name": to_name,
                                    "duration": call.get("duration", call.get("duration_seconds", 0)),
                                    "direction": call.get("direction", "unknown"),
                                    "timestamp": call.get("timestamp", ""),
                                    "source_file": filename
                                })
                        
                        # Collect files
                        for file_item in device.get("files", []):
                            if isinstance(file_item, dict):
                                filename_ext = file_item.get("filename", "")
                                exploration_data["files"].append({
                                    "filename": filename_ext,
                                    "size_bytes": file_item.get("size_bytes", 0),
                                    "file_type": filename_ext.split(".")[-1].lower() if "." in filename_ext else "unknown",
                                    "source_file": filename,
                                    "sensitive": any(keyword in filename_ext.lower() for keyword in ["password", "secret", "confidential"])
                                })
        
        return jsonify({
            "status": "SUCCESS",
            "data": exploration_data,
            "counts": {
                "contacts": len(exploration_data["contacts"]),
                "messages": len(exploration_data["messages"]),
                "calls": len(exploration_data["calls"]),
                "files": len(exploration_data["files"])
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching exploration data: {str(e)}")
        return jsonify({
            "status": "ERROR",
            "message": f"Error fetching data: {str(e)}"
        })

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    """Export forensic analysis and chat history as a court-presentable PDF document."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({
            "status": "ERROR",
            "message": "PDF export is not available. Please install reportlab: pip install reportlab"
        }), 500
    
    try:
        data = request.get_json() or {}
        export_type = data.get('type', 'full')  # 'full', 'chat', 'analysis'
        
        # Get current data
        data_src = get_current_data()
        if not data_src and export_type != 'chat':
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Get chat history if available
        chat_history = []
        if 'session_id' in session:
            session_id = session['session_id']
            chat_history = CHAT_HISTORIES.get(session_id, [])
            logger.info(f"Retrieved {len(chat_history)} chat messages from session {session_id}")
        else:
            logger.warning("No session_id found, chat history will be empty")
        
        # Also check if chat history is provided in the request (from frontend)
        if not chat_history and 'chat_history' in data:
            chat_history = data.get('chat_history', [])
            logger.info(f"Retrieved {len(chat_history)} chat messages from request data")
        
        # Log chat history status
        if not chat_history:
            logger.warning(f"No chat history available for export_type={export_type}")
        else:
            logger.info(f"Chat history available: {len(chat_history)} messages, export_type={export_type}")
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        
        # Title style
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Subtitle style
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=20,
            alignment=TA_LEFT,
            fontName='Helvetica-Bold'
        )
        
        # Body style
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#0f3460'),
            spaceAfter=12,
            alignment=TA_LEFT,  # Changed from JUSTIFY to LEFT for better readability
            leading=16,  # Increased line spacing
            leftIndent=0,
            rightIndent=0
        )
        
        # Header style
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#533483'),
            spaceAfter=8,
            spaceBefore=8,
            alignment=TA_LEFT,
            fontName='Helvetica-Bold',
            leading=14
        )
        
        # Add Title Page
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", title_style))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("EVI SCAN - AI-Powered Forensic Investigation System", 
                                  ParagraphStyle('Subtitle', parent=styles['Normal'], 
                                                fontSize=14, alignment=TA_CENTER, 
                                                textColor=colors.HexColor('#533483'))))
        elements.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        report_date = datetime.now().strftime("%B %d, %Y at %I:%M %p")
        report_info = [
            ['Report Generated:', report_date],
            ['System Version:', 'EVI SCAN v3.0.0'],
            ['Analysis Type:', 'Digital Forensic Investigation'],
        ]
        
        if ACTIVE_FILENAME:
            report_info.append(['Source File:', ACTIVE_FILENAME])
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8e8e8')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(info_table)
        elements.append(PageBreak())
        
        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", subtitle_style))
        elements.append(Spacer(1, 0.2*inch))
        
        summary_text = """
        This report presents a comprehensive digital forensic analysis conducted using the EVI SCAN 
        AI-Powered Forensic Investigation System. The analysis examines digital evidence extracted 
        from UFDR (Unified Forensic Data Records) files, including communications, contacts, 
        call logs, and file metadata.
        
        The investigation employs advanced pattern recognition, natural language processing, and 
        artificial intelligence to identify suspicious activities, security threats, and potential 
        evidence of criminal or unauthorized behavior.
        """
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Data Analysis Section
        if data_src and export_type in ['full', 'analysis']:
            elements.append(Paragraph("DATA ANALYSIS", subtitle_style))
            elements.append(Spacer(1, 0.2*inch))
            
            for filename, file_data in data_src.items():
                elements.append(Paragraph(f"Source File: {filename}", header_style))
                elements.append(Spacer(1, 0.1*inch))
                
                # Extract key statistics
                stats = []
                if isinstance(file_data, dict):
                    total_records = 0
                    if 'messages' in file_data:
                        total_records += len(file_data.get('messages', []))
                    if 'contacts' in file_data:
                        total_records += len(file_data.get('contacts', []))
                    if 'call_logs' in file_data:
                        total_records += len(file_data.get('call_logs', []))
                    
                    stats.append(['Total Records Analyzed:', str(total_records)])
                    
                    if 'messages' in file_data:
                        stats.append(['Messages:', str(len(file_data.get('messages', [])))])
                    if 'contacts' in file_data:
                        stats.append(['Contacts:', str(len(file_data.get('contacts', [])))])
                    if 'call_logs' in file_data:
                        stats.append(['Call Logs:', str(len(file_data.get('call_logs', [])))])
                
                if stats:
                    stats_table = Table(stats, colWidths=[3*inch, 3*inch])
                    stats_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f3460')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(stats_table)
                    elements.append(Spacer(1, 0.2*inch))
        
        # Chat History / Investigation Log
        if export_type in ['full', 'chat']:
            if chat_history and len(chat_history) > 0:
                elements.append(PageBreak())
                elements.append(Paragraph("INVESTIGATION LOG", subtitle_style))
                elements.append(Spacer(1, 0.2*inch))
                
                elements.append(Paragraph(
                    "The following section documents the interactive investigation session, including "
                    "queries posed to the forensic AI system and corresponding analysis results.",
                    body_style
                ))
                elements.append(Spacer(1, 0.2*inch))
                
                query_count = 0
                for idx, msg in enumerate(chat_history, 1):
                    role = msg.get('role', 'unknown')
                    content = msg.get('content', '')
                    timestamp = msg.get('timestamp', '')
                    
                    if not content or not content.strip():
                        continue
                    
                    if role == 'user':
                        query_count += 1
                        elements.append(Spacer(1, 0.2*inch))
                        elements.append(Paragraph(f"<b>Investigator Query #{query_count}</b>", header_style))
                        if timestamp:
                            # Format timestamp nicely
                            try:
                                from datetime import datetime as dt
                                if 'T' in timestamp:
                                    dt_obj = dt.fromisoformat(timestamp.replace('Z', '+00:00'))
                                    formatted_time = dt_obj.strftime("%B %d, %Y at %I:%M %p")
                                else:
                                    formatted_time = timestamp
                            except:
                                formatted_time = timestamp
                            elements.append(Paragraph(f"<i>Time: {formatted_time}</i>", 
                                                     ParagraphStyle('Timestamp', parent=styles['Normal'], 
                                                                   fontSize=9, textColor=colors.grey)))
                        elements.append(Spacer(1, 0.15*inch))
                        # Clean HTML and format
                        clean_content = content.replace('<', '&lt;').replace('>', '&gt;')
                        # Remove HTML tags but keep text
                        import re
                        clean_content = re.sub(r'<[^>]+>', '', clean_content)
                        # Break long lines and format properly
                        clean_content = clean_content.strip()
                        # Wrap long text
                        if len(clean_content) > 100:
                            # Add line breaks for readability
                            words = clean_content.split()
                            lines = []
                            current_line = []
                            current_length = 0
                            for word in words:
                                if current_length + len(word) + 1 > 80:
                                    lines.append(' '.join(current_line))
                                    current_line = [word]
                                    current_length = len(word)
                                else:
                                    current_line.append(word)
                                    current_length += len(word) + 1
                            if current_line:
                                lines.append(' '.join(current_line))
                            clean_content = '<br/>'.join(lines)
                        elements.append(Paragraph(clean_content, body_style))
                        elements.append(Spacer(1, 0.25*inch))
                    elif role == 'assistant':
                        elements.append(Spacer(1, 0.3*inch))
                        elements.append(Paragraph("<b>AI Forensic Analysis Response</b>", header_style))
                        elements.append(Spacer(1, 0.25*inch))
                        
                        # Clean and format response
                        import re
                        clean_content = content.replace('<', '&lt;').replace('>', '&gt;')
                        clean_content = re.sub(r'<[^>]+>', '', clean_content)  # Remove HTML tags
                        
                        # Split by major section headers
                        section_pattern = r'(INVESTIGATION FINDINGS|SECURITY CONCERNS|EVIDENCE PATTERNS|RECOMMENDATIONS):'
                        parts = re.split(section_pattern, clean_content, flags=re.IGNORECASE)
                        
                        if len(parts) > 1:
                            # Process structured sections
                            for i in range(1, len(parts), 2):
                                if i + 1 < len(parts):
                                    section_title = parts[i].strip()
                                    section_content = parts[i + 1].strip()
                                    
                                    # Add section title with proper spacing
                                    section_title_style = ParagraphStyle(
                                        'SectionTitle',
                                        parent=styles['Normal'],
                                        fontSize=13,
                                        textColor=colors.HexColor('#533483'),
                                        spaceAfter=14,
                                        spaceBefore=18,
                                        fontName='Helvetica-Bold',
                                        leading=18
                                    )
                                    elements.append(Paragraph(f"<b>{section_title}:</b>", section_title_style))
                                    elements.append(Spacer(1, 0.18*inch))
                                    
                                    # Process section content - handle nested bullets
                                    lines = section_content.split('\n')
                                    
                                    current_main_bullet = None
                                    sub_bullets = []
                                    
                                    for line in lines:
                                        line = line.strip()
                                        if not line:
                                            continue
                                        
                                        # Check for main bullet with bold label: **Label:** followed by text or sub-bullets
                                        bold_bullet_match = re.match(r'^\*\*([^:]+):\*\*\s*(.*)', line)
                                        
                                        if bold_bullet_match:
                                            # Save previous main bullet if exists
                                            if current_main_bullet:
                                                # Render previous main bullet
                                                main_bullet_style = ParagraphStyle(
                                                    'MainBullet',
                                                    parent=body_style,
                                                    leftIndent=20,
                                                    bulletIndent=10,
                                                    spaceAfter=10,
                                                    spaceBefore=8,
                                                    leading=17,
                                                    fontName='Helvetica-Bold'
                                                )
                                                elements.append(Paragraph(current_main_bullet, main_bullet_style))
                                                
                                                # Render sub-bullets if any
                                                if sub_bullets:
                                                    for sub_bullet in sub_bullets:
                                                        sub_bullet_style = ParagraphStyle(
                                                            'SubBullet',
                                                            parent=body_style,
                                                            leftIndent=40,
                                                            bulletIndent=20,
                                                            spaceAfter=8,
                                                            spaceBefore=4,
                                                            leading=16,
                                                            fontSize=10.5
                                                        )
                                                        sub_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', sub_bullet)
                                                        elements.append(Paragraph(f"• {sub_text}", sub_bullet_style))
                                                    elements.append(Spacer(1, 0.1*inch))
                                                    sub_bullets = []
                                            
                                            # Start new main bullet
                                            label = bold_bullet_match.group(1)
                                            text = bold_bullet_match.group(2).strip()
                                            
                                            if text:
                                                current_main_bullet = f"• <b>{label}:</b> {text}"
                                            else:
                                                current_main_bullet = f"• <b>{label}:</b>"
                                        
                                        # Check for sub-bullet (indented or starts with bullet after main bullet)
                                        elif current_main_bullet and (re.match(r'^\s+[•\-\*]\s+', line) or re.match(r'^[•\-\*]\s+', line)):
                                            # This is a sub-bullet
                                            sub_bullet_text = re.sub(r'^[•\-\*]\s+', '', line).strip()
                                            sub_bullet_text = re.sub(r'^\s+[•\-\*]\s+', '', sub_bullet_text).strip()
                                            sub_bullet_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', sub_bullet_text)
                                            sub_bullets.append(sub_bullet_text)
                                        
                                        # Check for regular bullet (not nested)
                                        elif re.match(r'^[•\-\*]\s+', line):
                                            # Save previous main bullet if exists
                                            if current_main_bullet:
                                                main_bullet_style = ParagraphStyle(
                                                    'MainBullet',
                                                    parent=body_style,
                                                    leftIndent=20,
                                                    bulletIndent=10,
                                                    spaceAfter=10,
                                                    spaceBefore=8,
                                                    leading=17
                                                )
                                                elements.append(Paragraph(current_main_bullet, main_bullet_style))
                                                
                                                if sub_bullets:
                                                    for sub_bullet in sub_bullets:
                                                        sub_bullet_style = ParagraphStyle(
                                                            'SubBullet',
                                                            parent=body_style,
                                                            leftIndent=40,
                                                            bulletIndent=20,
                                                            spaceAfter=8,
                                                            spaceBefore=4,
                                                            leading=16,
                                                            fontSize=10.5
                                                        )
                                                        sub_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', sub_bullet)
                                                        elements.append(Paragraph(f"• {sub_text}", sub_bullet_style))
                                                    elements.append(Spacer(1, 0.1*inch))
                                                    sub_bullets = []
                                            
                                            # Regular bullet point
                                            bullet_text = re.sub(r'^[•\-\*]\s+', '', line)
                                            bullet_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', bullet_text)
                                            
                                            bullet_style = ParagraphStyle(
                                                'BulletPoint',
                                                parent=body_style,
                                                leftIndent=20,
                                                bulletIndent=10,
                                                spaceAfter=12,
                                                spaceBefore=6,
                                                leading=16
                                            )
                                            
                                            elements.append(Paragraph(f"• {bullet_text}", bullet_style))
                                            current_main_bullet = None
                                        
                                        else:
                                            # Regular text - add to current main bullet or as paragraph
                                            if current_main_bullet:
                                                # Append to current main bullet
                                                text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', line)
                                                if current_main_bullet.endswith(':'):
                                                    current_main_bullet += f" {text}"
                                                else:
                                                    current_main_bullet += f" {text}"
                                            else:
                                                # Regular paragraph
                                                para_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', line)
                                                
                                                para_style = ParagraphStyle(
                                                    'Paragraph',
                                                    parent=body_style,
                                                    spaceAfter=14,
                                                    spaceBefore=6,
                                                    leading=17
                                                )
                                                
                                                elements.append(Paragraph(para_text, para_style))
                                    
                                    # Render last main bullet if exists
                                    if current_main_bullet:
                                        main_bullet_style = ParagraphStyle(
                                            'MainBullet',
                                            parent=body_style,
                                            leftIndent=20,
                                            bulletIndent=10,
                                            spaceAfter=10,
                                            spaceBefore=8,
                                            leading=17,
                                            fontName='Helvetica-Bold'
                                        )
                                        elements.append(Paragraph(current_main_bullet, main_bullet_style))
                                        
                                        if sub_bullets:
                                            for sub_bullet in sub_bullets:
                                                sub_bullet_style = ParagraphStyle(
                                                    'SubBullet',
                                                    parent=body_style,
                                                    leftIndent=40,
                                                    bulletIndent=20,
                                                    spaceAfter=8,
                                                    spaceBefore=4,
                                                    leading=16,
                                                    fontSize=10.5
                                                )
                                                sub_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', sub_bullet)
                                                elements.append(Paragraph(f"• {sub_text}", sub_bullet_style))
                                            elements.append(Spacer(1, 0.1*inch))
                                    
                                    elements.append(Spacer(1, 0.35*inch))
                        else:
                            # No structured sections - format as regular paragraphs
                            clean_content = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', clean_content)
                            paragraphs = re.split(r'\n{2,}', clean_content)
                            
                            for para in paragraphs:
                                para = para.strip().replace('\n', ' ')
                                if not para:
                                    continue
                                
                                para_style = ParagraphStyle(
                                    'Paragraph',
                                    parent=body_style,
                                    spaceAfter=18,
                                    spaceBefore=8,
                                    leading=17
                                )
                                
                                elements.append(Paragraph(para, para_style))
                        
                        elements.append(Spacer(1, 0.4*inch))
            else:
                # Add a note if no chat history
                if export_type == 'chat':
                    elements.append(PageBreak())
                    elements.append(Paragraph("INVESTIGATION LOG", subtitle_style))
                    elements.append(Spacer(1, 0.2*inch))
                    elements.append(Paragraph(
                        "<i>No chat history available for this session. Please ensure you have "
                        "interacted with the AI chat assistant before exporting.</i>",
                        ParagraphStyle('NoChat', parent=styles['Normal'], 
                                      fontSize=10, textColor=colors.grey, alignment=TA_CENTER)
                    ))
                    elements.append(Spacer(1, 0.2*inch))
        
        # Findings and Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("FINDINGS AND RECOMMENDATIONS", subtitle_style))
        elements.append(Spacer(1, 0.2*inch))
        
        findings_text = """
        Based on the comprehensive analysis conducted, this report provides detailed findings 
        regarding the digital evidence examined. All conclusions are based on the data available 
        in the provided UFDR files and the AI-powered analysis performed by the EVI SCAN system.
        
        <b>Note:</b> This report is generated for investigative purposes and should be reviewed 
        by qualified forensic experts before use in legal proceedings.
        """
        elements.append(Paragraph(findings_text, body_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Footer/Disclaimer
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph(
            "<i>This report was automatically generated by the EVI SCAN Forensic Analysis System. "
            "For questions or additional analysis, please contact the forensic investigation team.</i>",
            ParagraphStyle('Disclaimer', parent=styles['Normal'], 
                          fontSize=9, textColor=colors.grey, alignment=TA_CENTER)
        ))
        
        # Build PDF
        try:
            doc.build(elements)
        except Exception as build_error:
            logger.error(f"Error building PDF: {str(build_error)}")
            raise
        
        buffer.seek(0)
        
        # Verify PDF was created (check if buffer has content)
        pdf_size = len(buffer.getvalue())
        if pdf_size == 0:
            logger.error("PDF buffer is empty")
            return jsonify({
                "status": "ERROR",
                "message": "Failed to generate PDF: Empty PDF buffer"
            }), 500
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Forensic_Report_{timestamp}.pdf"
        
        # Create response with proper headers
        response = send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
        # Add security headers to prevent browser warnings
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Length'] = str(pdf_size)
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "ERROR",
            "message": f"Error generating PDF: {str(e)}"
        }), 500

@app.route('/api/media/<path:filename>')
def serve_media(filename):
    """
    Serve media files (images) from the UFDR Media folder or ZIP extraction.
    Handles both regular Media/images/ structure and ZIP-extracted images.
    """
    try:
        # Security: prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({"status": "ERROR", "message": "Invalid filename"}), 400
        
        # First, check if we have ZIP-extracted images
        data_src = get_current_data()
        zip_extracted_path = None
        
        # Normalize the filename parameter (handle URL encoding)
        import urllib.parse
        decoded_filename = urllib.parse.unquote(filename)
        
        # Check for ZIP info at top level
        if data_src and '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                # Find the image by matching rel_path or name
                for img_info in zip_info.get('images', []):
                    rel_path = img_info.get('rel_path', '')
                    img_name = img_info.get('name', '')
                    # Match by full rel_path, or by filename, or if rel_path ends with filename
                    if (rel_path == decoded_filename or 
                        img_name == decoded_filename or 
                        rel_path.endswith(decoded_filename) or
                        decoded_filename in rel_path):
                        zip_extracted_path = img_info.get('path')
                        if zip_extracted_path and os.path.exists(zip_extracted_path):
                            break
        
        # Also check in file data
        if not zip_extracted_path and data_src:
            for file_data in data_src.values():
                if isinstance(file_data, dict) and '_zip_info' in file_data:
                    zip_info = file_data.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        for img_info in zip_info.get('images', []):
                            rel_path = img_info.get('rel_path', '')
                            img_name = img_info.get('name', '')
                            if (rel_path == decoded_filename or 
                                img_name == decoded_filename or 
                                rel_path.endswith(decoded_filename) or
                                decoded_filename in rel_path):
                                zip_extracted_path = img_info.get('path')
                                if zip_extracted_path and os.path.exists(zip_extracted_path):
                                    break
                    if zip_extracted_path:
                        break
        
        # If found in ZIP extraction, serve from there
        if zip_extracted_path and os.path.exists(zip_extracted_path):
            # Determine MIME type from file extension
            ext = os.path.splitext(filename)[1].lower()
            mime_types = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.bmp': 'image/bmp',
                '.webp': 'image/webp'
            }
            mimetype = mime_types.get(ext, 'image/jpeg')
            return send_file(zip_extracted_path, mimetype=mimetype)
        
        # Otherwise, try to find media folder relative to uploaded UFDR file
        media_paths = []
        
        # Option 1: Check relative to uploaded UFDR file
        if ACTIVE_FILENAME:
            ufdr_dir = os.path.dirname(ACTIVE_FILENAME) if os.path.dirname(ACTIVE_FILENAME) else UPLOAD_FOLDER
            media_paths.append(os.path.join(ufdr_dir, "Media", "images", filename))
            # Also check parent directory (for UFDRBuilder structure)
            parent_dir = os.path.dirname(ufdr_dir) if os.path.dirname(ufdr_dir) else ufdr_dir
            media_paths.append(os.path.join(parent_dir, "Media", "images", filename))
        
        # Option 2: Check in upload folder
        media_paths.append(os.path.join(UPLOAD_FOLDER, "Media", "images", filename))
        
        # Option 3: Check in data folder
        media_paths.append(os.path.join("data", "Media", "images", filename))
        
        # Try each path
        for media_path in media_paths:
            if os.path.exists(media_path) and os.path.isfile(media_path):
                # Verify it's an image file
                ext = os.path.splitext(filename)[1].lower()
                if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
                    # Determine MIME type
                    mime_types = {
                        '.jpg': 'image/jpeg',
                        '.jpeg': 'image/jpeg',
                        '.png': 'image/png',
                        '.gif': 'image/gif',
                        '.bmp': 'image/bmp',
                        '.webp': 'image/webp'
                    }
                    mimetype = mime_types.get(ext, 'image/jpeg')
                    return send_file(media_path, mimetype=mimetype)
        
        # Image not found
        logger.warning(f"Image not found: {filename}. Tried paths: {media_paths}")
        return jsonify({
            "status": "ERROR",
            "message": f"Image not found: {filename}",
            "tried_paths": media_paths
        }), 404
        
    except Exception as e:
        logger.error(f"Error serving media file {filename}: {e}")
        return jsonify({
            "status": "ERROR",
            "message": f"Error serving image: {str(e)}"
        }), 500


@app.route('/api/debug/rbac', methods=['GET'])
@login_required
def debug_rbac():
    """Debug endpoint to check RBAC permissions for current user."""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        email = session.get('email')
        
        if not user_id:
            return jsonify({
                "error": "Not logged in",
                "user_id": None,
                "session_data": dict(session)
            }), 401
        
        # Ensure user_id is integer
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "error": f"Invalid user_id type: {user_id} (type: {type(user_id).__name__})",
                "user_id": user_id,
                "session_data": dict(session)
            }), 400
        
        if not SECURITY_AVAILABLE:
            return jsonify({
                "error": "Security module not available",
                "SECURITY_AVAILABLE": False,
                "user_id": user_id,
                "username": username,
                "email": email
            }), 500
        
        user_role = RBAC.get_user_role(user_id)
        has_audit_permission = RBAC.has_permission('view_audit_logs', user_id)
        has_manage_users = RBAC.has_permission('manage_users', user_id)
        
        # Get all permissions for this role
        role_permissions = RBAC.ROLES.get(user_role, [])
        
        # Check database path
        current_file = os.path.abspath(__file__)
        security_dir = os.path.dirname(os.path.join(os.path.dirname(current_file), 'security', 'security_enhancements.py'))
        forensic_dir = os.path.dirname(current_file)
        evi_scan_dir = os.path.dirname(forensic_dir)
        auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')
        
        # Get user info from database to verify
        try:
            import sqlite3
            conn = sqlite3.connect(auth_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, email, username, role FROM users WHERE id = ?", (user_id,))
            db_user = cur.fetchone()
            conn.close()
            
            db_role = db_user['role'] if db_user else None
            db_email = db_user['email'] if db_user else None
        except Exception as db_error:
            db_role = None
            db_email = None
            logger.warning(f"Could not verify user in database: {db_error}")
        
        return jsonify({
            "user_id": user_id,
            "username": username,
            "email": email,
            "user_role": user_role,
            "db_role": db_role,
            "db_email": db_email,
            "has_view_audit_logs": has_audit_permission,
            "has_manage_users": has_manage_users,
            "role_permissions": role_permissions,
            "available_roles": list(RBAC.ROLES.keys()),
            "auth_db_path": auth_db,
            "auth_db_exists": os.path.exists(auth_db),
            "SECURITY_AVAILABLE": SECURITY_AVAILABLE,
            "session_keys": list(session.keys())
        })
    except Exception as e:
        logger.error(f"Error in debug_rbac: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "traceback": str(e.__traceback__) if hasattr(e, '__traceback__') else None
        }), 500

@app.route('/api/debug/active-data', methods=['GET'])
@login_required
def debug_active_data():
    """Diagnostic endpoint to check what data is loaded in ACTIVE_DATA"""
    try:
        global ACTIVE_DATA, ACTIVE_FILENAME
        
        debug_info = {
            "active_filename": ACTIVE_FILENAME,
            "active_data_keys": list(ACTIVE_DATA.keys()) if ACTIVE_DATA else [],
            "active_data_count": len(ACTIVE_DATA) if ACTIVE_DATA else 0,
            "data_summary": {}
        }
        
        # Analyze each file in ACTIVE_DATA
        for filename, data in ACTIVE_DATA.items():
            if filename.startswith('_'):
                debug_info["data_summary"][filename] = {"type": "metadata", "content": str(data)[:200]}
                continue
            
            file_summary = {
                "type": "ufdr_data",
                "is_dict": isinstance(data, dict),
                "keys": list(data.keys()) if isinstance(data, dict) else []
            }
            
            if isinstance(data, dict):
                # Check for devices array
                if 'devices' in data and isinstance(data['devices'], list):
                    devices = data['devices']
                    file_summary["devices_count"] = len(devices)
                    file_summary["devices"] = []
                    for i, device in enumerate(devices):
                        if isinstance(device, dict):
                            device_info = {
                                "device_index": i,
                                "contacts_count": len(device.get('contacts', [])),
                                "messages_count": len(device.get('messages', [])),
                                "call_logs_count": len(device.get('call_logs', [])),
                                "device_info": device.get('device', {})
                            }
                            file_summary["devices"].append(device_info)
                else:
                    # Flat structure
                    file_summary["contacts_count"] = len(data.get('contacts', []))
                    file_summary["messages_count"] = len(data.get('messages', []))
                    file_summary["call_logs_count"] = len(data.get('call_logs', []))
            
            debug_info["data_summary"][filename] = file_summary
        
        return jsonify({
            "status": "SUCCESS",
            "debug_info": debug_info
        })
    except Exception as e:
        logger.error(f"Error in debug_active_data: {e}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route('/audit-logs')
@login_required
def view_audit_logs():
    """View audit logs - Chain of Custody (Admin and Auditor only)"""
    try:
        # RBAC: Check permission - Admin and Auditor only
        if not SECURITY_AVAILABLE:
            logger.error("SECURITY_AVAILABLE is False - security enhancements not loaded")
            flash('🔒 Security module not available. Audit logs cannot be accessed.', 'error')
            return redirect('/case-manager')
        
        try:
            user_id = session.get('user_id')
            if not user_id:
                logger.error("No user_id in session")
                flash('🔒 Not logged in. Please log in to access audit logs.', 'error')
                return redirect('/case-manager')
            
            # Ensure user_id is an integer (session might store it as string)
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                logger.error(f"Invalid user_id in session: {user_id} (type: {type(user_id)})")
                flash('🔒 Invalid session. Please log in again.', 'error')
                return redirect('/case-manager')
            
            logger.info(f"🔍 Audit logs access check - User ID: {user_id} (type: {type(user_id).__name__})")
            
            # Get user role
            try:
                user_role = RBAC.get_user_role(user_id)
                logger.info(f"   → User role: {user_role}")
            except Exception as role_error:
                logger.error(f"   ❌ Error getting user role: {role_error}", exc_info=True)
                flash(f'🔒 Access Denied: Unable to verify user role. Error: {str(role_error)}. Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            # Check permission
            try:
                has_permission = RBAC.has_permission('view_audit_logs', user_id)
                logger.info(f"   → Has 'view_audit_logs' permission: {has_permission}")
            except Exception as perm_error:
                logger.error(f"   ❌ Error checking permission: {perm_error}", exc_info=True)
                flash(f'🔒 Access Denied: Unable to verify permissions. Error: {str(perm_error)}. Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            # Debug: Check what permissions the role has
            if user_role in RBAC.ROLES:
                role_permissions = RBAC.ROLES[user_role]
                logger.info(f"   → Role '{user_role}' has permissions: {role_permissions}")
                logger.info(f"   → 'view_audit_logs' in permissions: {'view_audit_logs' in role_permissions}")
            else:
                logger.warning(f"   ⚠️ Role '{user_role}' not found in RBAC.ROLES. Available roles: {list(RBAC.ROLES.keys())}")
                # If role not found, deny access
                flash(f'🔒 Access Denied: Unknown role "{user_role}". Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            if not has_permission:
                logger.warning(f"   ❌ User {user_id} (role: {user_role}) denied access to audit logs")
                # Show user-friendly error message with role info
                flash(f'🔒 Access Denied: You do not have permission to access Audit Logs. Your role is "{user_role}". This section is restricted to Administrators and Auditors only.', 'error')
                return redirect('/case-manager')
            
            logger.info(f"   ✅ User {user_id} (role: {user_role}) granted access to audit logs")
        except Exception as e:
            logger.error(f"❌ RBAC check failed for audit logs: {e}", exc_info=True)
            # Deny access if RBAC check fails (security-first approach)
            flash(f'🔒 Access Denied: Unable to verify permissions. Error: {str(e)}. Please contact your administrator.', 'error')
            return redirect('/case-manager')
        
        if not SESSION_DB_AVAILABLE:
            flash('Session database not available', 'error')
            return redirect('/case-manager')
        
        # Get audit logs from database
        import sys
        import os
        _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
        if _database_code_path not in sys.path:
            sys.path.insert(0, _database_code_path)
        from session_db import get_db_connection
        
        conn = get_db_connection()
        if not conn:
            flash('Could not connect to database', 'error')
            return redirect('/case-manager')
        
        # Get filter parameters
        limit = request.args.get('limit', 100, type=int)
        action_filter = request.args.get('action', None)
        user_filter = request.args.get('user_id', None, type=int)
        
        cur = conn.cursor()
        
        # Build query
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        
        if action_filter:
            query += " AND action LIKE ?"
            params.append(f"%{action_filter}%")
        
        if user_filter:
            query += " AND user_id = ?"
            params.append(user_filter)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        # Ensure row factory is set (get_db_connection should already set it, but ensure it)
        if not hasattr(conn, 'row_factory') or conn.row_factory is None:
            conn.row_factory = sqlite3.Row
        
        cur.execute(query, params)
        rows = cur.fetchall()
        
        # Convert rows to dictionaries
        logs = []
        for row in rows:
            if isinstance(row, sqlite3.Row):
                log_dict = {key: row[key] for key in row.keys()}
            else:
                # Fallback if row is not a Row object
                column_names = [description[0] for description in cur.description]
                log_dict = dict(zip(column_names, row))
            logs.append(log_dict)
        
        # Audit logging: Log that audit logs were viewed
        if SECURITY_AVAILABLE and audit_logger:
            user_role = RBAC.get_user_role() if SECURITY_AVAILABLE else 'unknown'
            audit_logger.log_action('view_audit_logs', resource='audit_logs', success=True,
                                  details={
                                      'role': user_role,
                                      'limit': limit,
                                      'filters': {
                                          'action': action_filter,
                                          'user_id': user_filter
                                      },
                                      'results_count': len(logs)
                                  })
        
        # Parse JSON details - keep as string for template rendering
        for log in logs:
            if log.get('details'):
                # If details is already a dict (from row factory), convert to JSON string
                if isinstance(log['details'], dict):
                    try:
                        log['details'] = json.dumps(log['details'], indent=2)
                    except:
                        log['details'] = str(log['details'])
                # If it's a string, try to parse and re-stringify for pretty printing
                elif isinstance(log['details'], str):
                    try:
                        parsed = json.loads(log['details'])
                        log['details'] = json.dumps(parsed, indent=2)
                    except:
                        # Keep as-is if not valid JSON
                        pass
        
        cur.close()
        conn.close()
        
        return render_template('security/audit_logs.html', logs=logs, 
                             action_filter=action_filter, user_filter=user_filter)
    except Exception as e:
        logger.error(f"Error viewing audit logs: {e}")
        flash(f'Error loading audit logs: {str(e)}', 'error')
        return redirect('/case-manager')

@app.route('/profile')
@login_required
def profile():
    """Profile page"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        email = session.get('email')
        name = session.get('name', '')
        
        # Get user info from database
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            flash('User not found', 'error')
            return redirect('/case-manager')
        
        user_data = dict(user) if user else {}
        cur.close()
        conn.close()
        
        return render_template('profile.html', 
                             user_id=user_id,
                             username=username or user_data.get('username', ''),
                             email=email or user_data.get('email', ''),
                             name=name or f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip(),
                             first_name=user_data.get('first_name', ''),
                             last_name=user_data.get('last_name', ''),
                             role=user_data.get('role', 'investigator'),
                             last_login=user_data.get('last_login', ''),
                             created_at=user_data.get('created_at', ''))
    except Exception as e:
        logger.error(f"Error loading profile: {e}")
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect('/case-manager')

@app.route('/api/profile/stats', methods=['GET'])
@login_required
def get_profile_stats():
    """Get profile statistics (active case count, recent activity)"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        # Get active case count
        active_cases = 0
        if SESSION_DB_AVAILABLE:
            cases = get_all_cases(status_filter='Active', created_by=username)
            active_cases = len(cases)
        
        # Get recent activity (last 10 audit log entries for this user)
        recent_activity = []
        if SECURITY_AVAILABLE:
            try:
                import sys
                import os
                _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
                if _database_code_path not in sys.path:
                    sys.path.insert(0, _database_code_path)
                from session_db import get_db_connection
                
                conn = get_db_connection()
                if conn:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT action, resource, timestamp, success, details
                        FROM audit_logs
                        WHERE user_id = ?
                        ORDER BY timestamp DESC
                        LIMIT 10
                    """, (str(user_id),))
                    rows = cur.fetchall()
                    for row in rows:
                        recent_activity.append({
                            'action': row['action'],
                            'resource': row['resource'],
                            'timestamp': row['timestamp'],
                            'success': row['success'],
                            'details': row['details']
                        })
                    cur.close()
                    conn.close()
            except Exception as e:
                logger.warning(f"Error getting recent activity: {e}")
        
        return jsonify({
            "status": "SUCCESS",
            "active_cases": active_cases,
            "recent_activity": recent_activity
        })
    except Exception as e:
        logger.error(f"Error getting profile stats: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        user_id = session.get('user_id')
        data = request.get_json() or {}
        
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip()
        username = data.get('username', '').strip()
        phone = data.get('phone', '').strip()
        location = data.get('location', '').strip()
        bio = data.get('bio', '').strip()
        
        if not first_name or not last_name or not email or not username:
            return jsonify({"status": "ERROR", "message": "All required fields are required"}), 400
        
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Check if columns exist, if not add them
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        
        if 'phone' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        if 'location' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN location TEXT")
        if 'bio' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN bio TEXT")
        if 'profile_picture' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
        
        # Check if email or username is already taken by another user
        cur.execute("SELECT id FROM users WHERE (email = ? OR username = ?) AND id != ?", (email, username, user_id))
        existing = cur.fetchone()
        if existing:
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "Email or username already taken"}), 400
        
        # Update user - build query dynamically based on available columns
        update_fields = []
        update_values = []
        
        update_fields.append("first_name = ?")
        update_values.append(first_name)
        update_fields.append("last_name = ?")
        update_values.append(last_name)
        update_fields.append("email = ?")
        update_values.append(email)
        update_fields.append("username = ?")
        update_values.append(username)
        
        if 'phone' in columns:
            update_fields.append("phone = ?")
            update_values.append(phone if phone else None)
        if 'location' in columns:
            update_fields.append("location = ?")
            update_values.append(location if location else None)
        if 'bio' in columns:
            update_fields.append("bio = ?")
            update_values.append(bio if bio else None)
        
        update_values.append(user_id)
        
        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cur.execute(update_query, update_values)
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Update session with all profile data (ensures persistence across server restarts)
        session['username'] = username
        session['email'] = email
        session['name'] = f"{first_name} {last_name}"
        if 'phone' in columns:
            session['phone'] = phone if phone else ''
        if 'location' in columns:
            session['location'] = location if location else ''
        if 'bio' in columns:
            session['bio'] = bio if bio else ''
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            updated_fields = ['first_name', 'last_name', 'email', 'username']
            if phone:
                updated_fields.append('phone')
            if location:
                updated_fields.append('location')
            if bio:
                updated_fields.append('bio')
            audit_logger.log_action('update_profile', resource=f"user_{user_id}", success=True,
                                  details={'updated_fields': updated_fields})
        
        return jsonify({"status": "SUCCESS", "message": "Profile updated successfully"})
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/upload-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    """Upload profile picture"""
    try:
        user_id = session.get('user_id')
        
        if 'file' not in request.files:
            return jsonify({"status": "ERROR", "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "ERROR", "message": "No file selected"}), 400
        
        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({"status": "ERROR", "message": "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP"}), 400
        
        # Create profile pictures directory
        profile_pics_dir = os.path.join(BASE_DIR, 'static', 'profile_pictures')
        os.makedirs(profile_pics_dir, exist_ok=True)
        
        # Generate unique filename
        file_ext = filename.rsplit('.', 1)[1].lower()
        new_filename = f"user_{user_id}_{secrets.token_hex(8)}.{file_ext}"
        filepath = os.path.join(profile_pics_dir, new_filename)
        
        # Save file
        file.save(filepath)
        
        # Update database
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if profile_picture column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        if 'profile_picture' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
        
        # Delete old profile picture if exists
        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
        old_pic = cur.fetchone()
        if old_pic and old_pic[0]:
            old_pic_path = os.path.join(profile_pics_dir, old_pic[0].replace('profile_pictures/', ''))
            if os.path.exists(old_pic_path):
                try:
                    os.remove(old_pic_path)
                except:
                    pass
        
        # Update database with new picture path
        relative_path = f"profile_pictures/{new_filename}"
        cur.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (relative_path, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        # Update session
        session['profile_picture'] = relative_path
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('upload_profile_picture', resource=f"user_{user_id}", success=True)
        
        return jsonify({
            "status": "SUCCESS",
            "message": "Profile picture uploaded successfully",
            "profile_picture": f"/static/{relative_path}"
        })
    except Exception as e:
        logger.error(f"Error uploading profile picture: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        data = request.get_json() or {}
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({"status": "ERROR", "message": "All password fields are required"}), 400
        
        if new_password != confirm_password:
            return jsonify({"status": "ERROR", "message": "New passwords do not match"}), 400
        
        if len(new_password) < 8:
            return jsonify({"status": "ERROR", "message": "Password must be at least 8 characters"}), 400
        
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Verify current password
        cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "User not found"}), 404
        
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "Current password is incorrect"}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('change_password', resource=f"user_{user_id}", success=True)
        
        return jsonify({"status": "SUCCESS", "message": "Password changed successfully"})
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/security', methods=['GET', 'POST'])
@login_required
def account_security():
    """Get or update account security settings"""
    try:
        user_id = session.get('user_id')
        
        if request.method == 'GET':
            # Get security settings
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT is_active, last_login, created_at FROM users WHERE id = ?", (user_id,))
            user = cur.fetchone()
            
            security_info = {
                'is_active': user['is_active'] if user else True,
                'last_login': user['last_login'] if user else None,
                'created_at': user['created_at'] if user else None,
                'two_factor_enabled': False,  # Placeholder for future 2FA
                'session_count': 1  # Placeholder
            }
            
            cur.close()
            conn.close()
            
            return jsonify({"status": "SUCCESS", "security": security_info})
        
        else:  # POST - Update security settings
            data = request.get_json() or {}
            # Placeholder for future security settings updates
            return jsonify({"status": "SUCCESS", "message": "Security settings updated"})
            
    except Exception as e:
        logger.error(f"Error with account security: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/chimes/<filename>')
def serve_chime(filename):
    """Serve chime sound files."""
    try:
        # Updated path to match new folder structure
        chime_path = os.path.join('static', 'chimes', filename)
        if os.path.exists(chime_path):
            from flask import send_file
            return send_file(chime_path, mimetype='audio/wav')
        else:
            # Try alternative path for backward compatibility
            alt_path = os.path.join('Chimes', filename)
            if os.path.exists(alt_path):
                from flask import send_file
                return send_file(alt_path, mimetype='audio/wav')
            return jsonify({"error": f"Chime file not found: {filename}"}), 404
    except Exception as e:
        return jsonify({"error": f"Error serving chime: {str(e)}"}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Load any existing uploaded files
    uploaded_count = load_uploaded_files()
    if uploaded_count > 0:
        print(f"Loaded {uploaded_count} existing uploaded files")
    # Build RAG index on startup
    rebuild_rag_index()
    
    print("Starting UFDR Forensic Command Engine Web Interface...")
    print("Open your browser and go to: http://localhost:5000")
    if DEV_MODE:
        print("⚠️  DEVELOPMENT MODE: Login is bypassed - you can access directly")
        print("⚠️  Set DEV_MODE=False in code or export DEV_MODE=False for production")
    # Use 'stat' reloader instead of 'watchdog' to avoid issues with file uploads
    # 'stat' is slower but more stable for file operations
    app.run(debug=True, host='0.0.0.0', port=5000, reloader_type='stat')
