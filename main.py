# main.py - Fixed escape sequences
"""
GhostTrigger - Modern Authentication Bypass Detection Tool
"""

import sys
import asyncio
from datetime import datetime
from colorama import init, Fore, Style

from config import TARGET_URL, USERNAME, PASSWORD, LOGIN_URL, REPORT_FILE
from crawler import WebCrawler
from analyzer import Analyzer
from exploiter import Exploiter
from reporter import Reporter

# Initialize colorama for colored output
init(autoreset=True)


def print_banner():
    banner = f"""
  █████╗ ██╗   ██╗ █████╗ ██████╗ 
 ██╔══██╗██║   ██║██╔══██╗██╔══██╗                               
 ███████║██║   ██║███████║██████╔╝                              
 ██╔══██║██║   ██║██╔══██║██╔══██╗                             
 ██║  ██║╚██████╔╝██║  ██║██████╔╝                                
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝                                
AUTOMATED UI-BASED AUTHENTICATION BYPASS                   
    """
    print(banner)


def print_summary(results: list, target_url: str, start_time: float):
    """Print colored summary of results"""
    elapsed = datetime.now().timestamp() - start_time
    total = len(results)
    successful = sum(1 for r in results if r.get("success"))
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.YELLOW} SCAN COMPLETE")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.WHITE} Target: {Fore.GREEN}{target_url}")
    print(f"{Fore.WHITE} Duration: {Fore.GREEN}{elapsed:.2f} seconds")
    print(f"{Fore.WHITE} Candidates Tested: {Fore.YELLOW}{total}")
    print(f"{Fore.WHITE} Successful Exploits: {Fore.GREEN if successful > 0 else Fore.RED}{successful}")
    
    if successful > 0:
        print(f"\n{Fore.GREEN}[+] VULNERABILITIES FOUND!")
        for r in results:
            if r.get("success"):
                cand = r.get("candidate", {})
                print(f"    • {Fore.RED}{cand.get('type', 'unknown').upper()}{Fore.WHITE} - {cand.get('exploit_description', 'No description')[:80]}")
    else:
        print(f"\n{Fore.YELLOW}[!] No vulnerabilities found. Try expanding scope or manual testing.")
    
    print(f"{Fore.CYAN}{'='*60}")


def main():
    print_banner()
    start_time = datetime.now().timestamp()
    
    # Step 1: Crawl the target
    print(f"\n{Fore.CYAN}[1/4]{Fore.WHITE} Crawling target and capturing traffic...")
    try:
        with WebCrawler(TARGET_URL, USERNAME, PASSWORD, LOGIN_URL) as crawler:
            page_data = crawler.run()
        print(f"{Fore.GREEN}[+] Crawling completed. Found {len(page_data.get('api_endpoints', []))} API endpoints.")
    except Exception as e:
        print(f"{Fore.RED}[!] Crawler failed: {e}")
        sys.exit(1)

    # Step 2: Analyze
    print(f"\n{Fore.CYAN}[2/4]{Fore.WHITE} Analyzing for vulnerabilities...")
    analyzer = Analyzer(page_data, use_llm=False)
    candidates = asyncio.run(analyzer.run())
    
    # Group candidates by severity
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for c in candidates:
        severity = c.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"{Fore.GREEN}[+] Found {len(candidates)} potential vulnerabilities:")
    print(f"    {Fore.RED}High: {severity_counts.get('high', 0)}")
    print(f"    {Fore.YELLOW}Medium: {severity_counts.get('medium', 0)}")
    print(f"    {Fore.WHITE}Low: {severity_counts.get('low', 0)}")
    print(f"    {Fore.BLUE}Info: {severity_counts.get('info', 0)}")

    if not candidates:
        print(f"\n{Fore.YELLOW}[!] No vulnerabilities found. Exiting.")
        sys.exit(0)

    # Step 3: Exploit
    print(f"\n{Fore.CYAN}[3/4]{Fore.WHITE} Attempting exploitation...")
    with Exploiter(TARGET_URL, candidates, page_data.get("cookies")) as exploiter:
        results = exploiter.run()

    # Step 4: Report
    print(f"\n{Fore.CYAN}[4/4]{Fore.WHITE} Generating report...")
    reporter = Reporter(TARGET_URL, results)
    report_path = REPORT_FILE.replace('.md', f'_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md')
    reporter.save(report_path)

    # Summary
    print_summary(results, TARGET_URL, start_time)
    print(f"\n{Fore.WHITE} Report saved to: {Fore.GREEN}{report_path}")


if __name__ == "__main__":
    main()