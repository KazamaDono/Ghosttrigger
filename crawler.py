# crawler.py - Simplified version without selenium-wire
"""
Enhanced Web Crawler with API traffic capture using Selenium only
"""

import time
import json
import re
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, urljoin

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup


class WebCrawler:
    def __init__(self, target_url: str, username: Optional[str] = None,
                 password: Optional[str] = None, login_url: Optional[str] = None):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.login_url = login_url or target_url
        self.driver = None
        self.base_domain = urlparse(target_url).netloc

    def __enter__(self):
        print("[*] Starting Chrome browser...")
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=options)
        
        # Execute script to hide webdriver property
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            self.driver.quit()
            print("[*] Browser closed.")

    def login(self) -> bool:
        if not self.username or not self.password:
            print("[*] No credentials provided, skipping login.")
            return True

        print(f"[*] Logging in to {self.login_url} ...")
        try:
            self.driver.get(self.login_url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.NAME, "username"))
            )
            self.driver.find_element(By.NAME, "username").send_keys(self.username)
            self.driver.find_element(By.NAME, "password").send_keys(self.password)
            
            # Try multiple submit button selectors
            submit_btn = self.driver.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
            if submit_btn:
                submit_btn[0].click()
            
            WebDriverWait(self.driver, 10).until(
                EC.url_changes(self.login_url)
            )
            print("[+] Login successful.")
            return True
        except Exception as e:
            print(f"[!] Login failed: {e}")
            return False

    def capture_network_logs(self) -> List[Dict[str, Any]]:
        """Capture network logs using Chrome DevTools Protocol"""
        logs = []
        try:
            # Enable performance logging
            self.driver.execute_cdp_cmd('Network.enable', {})
            
            # Get performance logs
            logs_raw = self.driver.get_log('performance')
            for entry in logs_raw:
                try:
                    log_data = json.loads(entry['message'])
                    message = log_data.get('message', {})
                    method = message.get('method', '')
                    
                    if method in ['Network.requestWillBeSent', 'Network.responseReceived']:
                        params = message.get('params', {})
                        request = params.get('request', {})
                        response = params.get('response', {})
                        
                        logs.append({
                            'method': request.get('method', 'UNKNOWN'),
                            'url': request.get('url', ''),
                            'headers': request.get('headers', {}),
                            'response_status': response.get('status', 0),
                            'response_headers': response.get('headers', {})
                        })
                except:
                    continue
        except:
            pass
        return logs

    def fetch_page(self, url: str) -> Dict[str, Any]:
        print(f"[*] Fetching {url}")
        self.driver.get(url)
        time.sleep(3)  # Wait for dynamic content
        
        # Enable network capture
        self.driver.execute_cdp_cmd('Network.enable', {})
        
        # Scroll to trigger lazy loading
        self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        
        html = self.driver.page_source
        with open("debug_page.html", "w", encoding="utf-8") as f:
            f.write(html)
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract JavaScript
        inline_js = []
        for script in soup.find_all('script'):
            if not script.get('src'):
                inline_js.append(script.string or "")
        
        external_js_urls = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        cookies = self.driver.get_cookies()
        
        # Extract API endpoints from HTML/JS
        api_endpoints = self._extract_api_endpoints(html, inline_js)
        
        # Extract JWT tokens from storage
        local_storage = self.driver.execute_script("return JSON.stringify(localStorage);")
        session_storage = self.driver.execute_script("return JSON.stringify(sessionStorage);")
        
        return {
            "url": self.driver.current_url,
            "html": html,
            "inline_js": inline_js,
            "external_js_urls": external_js_urls,
            "cookies": cookies,
            "api_endpoints": api_endpoints,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "page_title": self.driver.title
        }

    def _extract_api_endpoints(self, html: str, js_blocks: List[str]) -> List[str]:
        """Extract potential API endpoints from HTML and JavaScript"""
        endpoints = set()
        
        # Common API patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/graphql)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.ajax\({\s*url:\s*["\']([^"\']+)["\']',
        ]
        
        all_text = html + " ".join(js_blocks)
        for pattern in patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    full_url = urljoin(self.target_url, match)
                    endpoints.add(full_url)
                elif match.startswith('http'):
                    endpoints.add(match)
        
        return list(endpoints)[:20]  # Limit to 20 endpoints

    def run(self) -> Dict[str, Any]:
        if not self.login():
            raise Exception("Login failed")
        return self.fetch_page(self.target_url)