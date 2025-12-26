# How the Prompt is Constructed and Fed to the LLM

## Overview

The EVI-SCAN application constructs a multi-part prompt that includes:
1. **System Message** - Instructions for the LLM on how to behave
2. **Conversation History** - Previous messages for context
3. **User Query** - The current question
4. **Forensic Data** - Extracted UFDR data relevant to the query

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER SENDS QUERY                             │
│              "What can you tell me about this UFDR file"        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 1: EXTRACT FORENSIC DATA                       │
│                                                                   │
│  ACTIVE_DATA (UFDR files)                                        │
│  ├── contacts: 200 records                                       │
│  ├── messages: 6,400 records                                    │
│  ├── call_logs: 1,100 records                                   │
│  └── device: metadata                                            │
│                                                                   │
│  ┌─────────────────────────────────────────────┐                │
│  │  SemanticDataExtractor.extract_relevant_data │                │
│  │  OR                                          │                │
│  │  EnhancedDataExtractor.extract_relevant_data │                │
│  │  OR                                          │                │
│  │  prepare_json_for_llm (JSON mode)           │                │
│  └─────────────────────────────────────────────┘                │
│                           │                                      │
│                           ▼                                      │
│  data_context = "=== CONTACTS ===\n...\n=== MESSAGES ===\n..."  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 2: BUILD MESSAGES ARRAY                        │
│                                                                   │
│  messages = []                                                   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Message 1: SYSTEM ROLE                                   │   │
│  │ ┌────────────────────────────────────────────────────┐   │   │
│  │ │ You are an elite digital forensics analyst...     │   │   │
│  │ │                                                    │   │   │
│  │ │ CORE CAPABILITIES:                                 │   │   │
│  │ │ - Deep analysis of messages, calls, contacts     │   │   │
│  │ │ - Timeline reconstruction                         │   │   │
│  │ │ - Pattern recognition                             │   │   │
│  │ │                                                    │   │   │
│  │ │ ANALYSIS METHODOLOGY:                             │   │   │
│  │ │ 1. QUERY FOCUS                                    │   │   │
│  │ │ 2. EVIDENCE IDENTIFICATION                       │   │   │
│  │ │ 3. CONTEXTUAL ANALYSIS                           │   │   │
│  │ │ ...                                               │   │   │
│  │ └────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Message 2-N: CONVERSATION HISTORY (if exists)           │   │
│  │ ┌────────────────────────────────────────────────────┐   │   │
│  │ │ {"role": "user", "content": "Previous question"}  │   │   │
│  │ │ {"role": "assistant", "content": "Previous answer"}│   │   │
│  │ │ ...                                                 │   │   │
│  │ └────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Last Message: USER ROLE                                   │   │
│  │ ┌────────────────────────────────────────────────────┐   │   │
│  │ │ QUESTION: What can you tell me about this UFDR    │   │   │
│  │ │           file                                      │   │   │
│  │ │                                                    │   │   │
│  │ │ Use the forensic data below to answer the         │   │   │
│  │ │ question above. Focus ONLY on answering the        │   │   │
│  │ │ specific question asked.                           │   │   │
│  │ │                                                    │   │   │
│  │ │ FORENSIC DATA:                                     │   │   │
│  │ │ === CONTACTS ===                                   │   │   │
│  │ │ [200 contacts with names, phones, etc.]           │   │   │
│  │ │                                                    │   │   │
│  │ │ === MESSAGES ===                                   │   │   │
│  │ │ [6,400 messages with content, timestamps, etc.]   │   │   │
│  │ │                                                    │   │   │
│  │ │ === CALL LOGS ===                                  │   │   │
│  │ │ [1,100 calls with durations, timestamps, etc.]    │   │   │
│  │ │                                                    │   │   │
│  │ │ === DEVICE METADATA ===                            │   │   │
│  │ │ [Device info, IMEI, model, etc.]                  │   │   │
│  │ └────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 3: PREPARE REQUEST PAYLOAD                     │
│                                                                   │
│  request_payload = {                                             │
│      "model": "Qwen/Qwen2.5-3B-Instruct",                       │
│      "messages": messages,  # Array from Step 2                 │
│      "temperature": 0.7,                                         │
│      "max_tokens": 8000,                                         │
│      "stream": True  # Enable streaming                          │
│  }                                                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 4: SEND TO LM STUDIO                           │
│                                                                   │
│  POST http://localhost:1234/v1/chat/completions                 │
│  Content-Type: application/json                                  │
│                                                                   │
│  {                                                               │
│    "model": "Qwen/Qwen2.5-3B-Instruct",                         │
│    "messages": [                                                 │
│      {"role": "system", "content": "..."},                      │
│      {"role": "user", "content": "..."},                        │
│      {"role": "assistant", "content": "..."},                   │
│      {"role": "user", "content": "QUESTION: ...\n\nFORENSIC..."}│
│    ],                                                            │
│    "temperature": 0.7,                                           │
│    "max_tokens": 8000,                                           │
│    "stream": true                                                 │
│  }                                                               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 5: STREAM RESPONSE                            │
│                                                                   │
│  LM Studio returns Server-Sent Events (SSE) stream:             │
│                                                                   │
│  data: {"choices":[{"delta":{"content":"Based"}}]}              │
│  data: {"choices":[{"delta":{"content":" on"}}]}               │
│  data: {"choices":[{"delta":{"content":" the"}}]}               │
│  data: {"choices":[{"delta":{"content":" evidence"}}]}          │
│  ...                                                             │
│  data: [DONE]                                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Detailed Code Flow

### 1. Data Extraction (`web_interface.py` lines 4896-5021)

```python
# Get data context from UFDR files
data_context = ""

if data_src:
    # Option 1: JSON extraction mode (if use_json_extraction=True)
    if use_json_extraction:
        json_context = prepare_json_for_llm(data, query, max_chars=500000)
        data_context += json_context
    
    # Option 2: Semantic extraction (default, Magnet AXIOM style)
    else:
        # Try semantic extractor first (uses RAG if available)
        try:
            extracted_context = semantic_extractor.extract_relevant_data(data, query)
        except:
            # Fallback to enhanced extractor
            extracted_context = enhanced_extractor.extract_relevant_data(data, query)
        
        data_context = extracted_context
    
    # Add image citations if query is about images
    if image_citation_extractor.is_image_query(query):
        image_info = image_citation_extractor.format_image_citations(image_citations)
        data_context += image_info
```

### 2. Message Construction (`web_interface.py` lines 5030-5100)

```python
messages = []

# Step 1: Add system message
messages.append({
    "role": "system",
    "content": """You are an elite digital forensics analyst...
    [Full system prompt with instructions]
    """
})

# Step 2: Add conversation history (if exists)
if session_id in CHAT_HISTORIES and CHAT_HISTORIES[session_id]:
    history_messages = CHAT_HISTORIES[session_id][:-1]  # Exclude current query
    for msg in history_messages:
        messages.append({
            "role": msg.get("role", "user"),
            "content": msg.get("content", "")
        })

# Step 3: Add current query with forensic data
if data_context:
    user_message = f"""QUESTION: {query}

Use the forensic data below to answer the question above. Focus ONLY on answering the specific question asked.

FORENSIC DATA:
{data_context}"""
else:
    user_message = query

messages.append({
    "role": "user",
    "content": user_message
})
```

### 3. Request Preparation (`web_interface.py` lines 5155-5162)

```python
request_payload = {
    "model": LLM_MODEL,  # "Qwen/Qwen2.5-3B-Instruct"
    "messages": messages,  # Array from Step 2
    "temperature": 0.7,
    "max_tokens": 8000,
    "stream": True  # Enable streaming
}
```

### 4. Send to LM Studio (`web_interface.py` lines 5166-5171)

```python
resp = requests.post(
    LLM_URL,  # "http://localhost:1234/v1/chat/completions"
    json=request_payload,
    timeout=90,
    stream=True  # Important: stream the response
)
```

### 5. Stream Processing (`web_interface.py` lines 5182-5239)

```python
# Process Server-Sent Events (SSE) stream
for line in resp.iter_lines():
    if line.startswith('data: '):
        chunk_data = json.loads(line[6:])  # Remove 'data: ' prefix
        
        if chunk_data.get('choices'):
            delta = chunk_data['choices'][0].get('delta', {})
            content = delta.get('content', '')
            
            if content:
                # Send token to client
                yield f"data: {json.dumps({'type': 'token', 'content': content})}\n\n"
```

## Data Extraction Methods

### Method 1: Semantic Extraction (Default)
- **File**: `core/semantic_data_extractor.py`
- **Uses**: RAG engine (if available) or keyword-based search
- **Extracts**: ALL relevant data chunks based on query semantics
- **Format**: Structured sections (CONTACTS, MESSAGES, CALL LOGS, etc.)

### Method 2: Enhanced Extraction (Fallback)
- **File**: `core/enhanced_data_extractor.py`
- **Uses**: Keyword matching and pattern detection
- **Extracts**: Relevant data based on query keywords
- **Format**: Structured sections with actual details

### Method 3: JSON Extraction (Optional)
- **File**: `web_interface.py` → `prepare_json_for_llm()`
- **Uses**: Direct JSON serialization
- **Extracts**: Full UFDR data as JSON (up to 500,000 chars)
- **Format**: Raw JSON that LLM parses directly

## Key Features

1. **No Truncation**: All relevant data is sent (no arbitrary limits)
2. **Query-Aware**: Only extracts data relevant to the user's query
3. **Context Preservation**: Includes conversation history for follow-up questions
4. **Structured Format**: Data is organized into clear sections
5. **Streaming**: Responses are streamed token-by-token for real-time display

## Example Prompt Structure

```
System Message (2,429 chars):
"You are an elite digital forensics analyst..."

Conversation History (if exists):
User: "Who called John?"
Assistant: "Based on the call logs, John received calls from..."

Current User Message (13,862 chars):
"QUESTION: What can you tell me about this UFDR file

Use the forensic data below to answer the question above.

FORENSIC DATA:
=== CONTACTS ===
[200 contacts with details]

=== MESSAGES ===
[6,400 messages with content]

=== CALL LOGS ===
[1,100 calls with durations]

=== DEVICE METADATA ===
[Device information]"
```

## Logging and Diagnostics

The system includes extensive logging:
- `📊 Final data_context length`: Shows how much data is extracted
- `🔍 QUERY VERIFICATION`: Confirms query is in the prompt
- `📤 Request details`: Shows message count and lengths
- `✅ Data section found`: Verifies forensic data is included
- `📥 Stream line X`: Shows each chunk received from LM Studio

## Summary

The prompt construction process:
1. **Extracts** relevant forensic data based on query
2. **Builds** a messages array with system instructions, history, and current query
3. **Formats** the user message with query + forensic data
4. **Sends** to LM Studio via HTTP POST with streaming enabled
5. **Processes** the streaming response token-by-token

This ensures the LLM has:
- ✅ Clear instructions on how to behave
- ✅ Context from previous conversations
- ✅ The specific question being asked
- ✅ All relevant forensic data to answer the question

