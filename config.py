# config.py
"""
GhostTrigger Configuration - Modern Web Application Security Testing
"""

import os
from typing import Optional, List

# ============================================================================
# TARGET SETTINGS
# ============================================================================
TARGET_URL = "http://127.0.0.1:5000"
LOGIN_URL = None
USERNAME = None
PASSWORD = None

# ============================================================================
# MODERN SECURITY CHECKS
# ============================================================================
# Enable/disable specific test categories
ENABLE_JWT_TESTS = True           # JWT alg:none, weak signatures
ENABLE_IDOR_TESTS = True          # Insecure Direct Object References
ENABLE_ROLE_HEADER_TESTS = True   # X-Role, X-Admin header injection
ENABLE_GRAPHQL_TESTS = True       # GraphQL introspection, field abuse
ENABLE_NOSQL_TESTS = True         # NoSQL injection in login/params
ENABLE_SSRF_TESTS = True          # Server-Side Request Forgery
ENABLE_SQLI_TESTS = True          # Basic SQL injection detection
ENABLE_HEADER_INJECTION = True    # Host header, X-Forwarded-For
ENABLE_PATH_TRAVERSAL = True      # ../ detection

# ============================================================================
# JWT SETTINGS
# ============================================================================
JWT_ALG_NONE_TEST = True
JWT_WEAK_SECRETS = ["secret", "password", "admin", "123456", "key"]
JWT_CLAIM_INJECTION = ["admin", "isAdmin", "role", "group"]

# ============================================================================
# IDOR SETTINGS
# ============================================================================
IDOR_TEST_RANGE = [1, 2, 3, 5, 10, 100, 999]  # IDs to try
IDOR_PATTERNS = [
    r'/(?:user|account|profile|order|document|invoice)/(\d+)',
    r'[?&](?:id|user_id|account_id|doc_id)=(\d+)',
    r'/(?:api/)?v\d+/(?:users|accounts)/(\d+)'
]

# ============================================================================
# ROLE HEADERS TO TEST
# ============================================================================
ROLE_HEADERS = [
    "X-Role", "X-Admin", "X-User-Role", "X-Permission",
    "X-Auth-Role", "X-User-Type", "X-Privilege",
    "X-Account-Type", "X-Access-Level", "X-Group"
]

# ============================================================================
# NOSQL INJECTION PAYLOADS
# ============================================================================
NOSQL_PAYLOADS = [
    {"$ne": ""}, {"$gt": ""}, {"$regex": ".*"},
    "admin' || '1'=='1", "admin' || 1==1--",
    "' || '1'=='1", "admin'--"
]

# ============================================================================
# SSRF TEST ENDPOINTS
# ============================================================================
SSRF_CALLBACK_SERVICES = ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080/"]

# ============================================================================
# GRAPHQL SETTINGS
# ============================================================================
GRAPHQL_COMMON_PATHS = ["/graphql", "/v1/graphql", "/graphiql", "/playground", "/query"]

# ============================================================================
# OUTPUT SETTINGS
# ============================================================================
REPORT_FILE = "ghosttrigger_report.md"
SAVE_RAW_REQUESTS = True
DEBUG_MODE = False

# ============================================================================
# LLM SETTINGS
# ============================================================================
LLM_BACKEND = "ollama"  # or "openai"
OLLAMA_MODEL = "deepseek-coder"
OPENAI_API_KEY = None
OPENAI_MODEL = "gpt-4"

# ============================================================================
# PERFORMANCE SETTINGS
# ============================================================================
REQUEST_TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 5
USER_AGENT = "GhostTrigger/2.0 Security Scanner"
