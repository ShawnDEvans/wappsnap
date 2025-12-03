#!/usr/bin/env python3
import argparse
import os
import time
import requests
import urllib3
import threading
import queue
import tempfile
from lxml import etree
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from requests.exceptions import Timeout, ConnectionError, SSLError, ProxyError

# --- Global Configuration and Resource Management ---
REPORTS_DIR = "reports"
MAX_THREADS = 8
VERBOSITY_LINE_WIDTH = 120

GLOBAL_REPORT_DATA = []
URL_COUNT_TOTAL = 0
URL_COUNT_COMPLETED = 0
URL_COUNT_FAILED = 0
COUNTER_LOCK = threading.Lock()
DRIVER_POOL = queue.Queue() # Queue to hold reusable WebDriver instances

# Disable the InsecureRequestWarning from requests when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Progress Meter Functions ---

def print_progress(total):
    """Prints the real-time progress meter to the console."""
    # The carriage return '\r' moves the cursor to the start of the line
    with COUNTER_LOCK:
        print(
            f"[*] ⏳ Processing: Total: {total} | Completed: {URL_COUNT_COMPLETED} | Failed: {URL_COUNT_FAILED}",
            end='\r',
            flush=True
        )

# --- Helper Functions ---

def get_nmap_urls(nmap_xml_file):
    """Extracts HTTP/HTTPS URLs from an Nmap XML file."""
    urls = set()
    try:
        tree = etree.parse(nmap_xml_file)
        for host in tree.xpath('//host'):
            ip = host.xpath('./address[@addrtype="ipv4"]/@addr')[0]
            for port in host.xpath('./ports/port[state/@state="open"]'):
                port_id = port.get('portid')
                service_name = port.xpath('./service/@name')
                if 'http' in service_name or port_id in ('80', '443', '8080', '8443'):
                    protocol = 'https' if port_id in ('443', '8443') else 'http'
                    urls.add(f"{protocol}://{ip}:{port_id}")
    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
    return list(urls)

def setup_webdriver(wait_time):
    """Initializes a headless Firefox WebDriver for the pool."""
    options = FirefoxOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,1024")

    # SSL Insecurity is the default behavior
    options.set_preference("security.mixed_content.block_active_content", False)
    options.set_preference("security.mixed_content.block_display_content", False)
    options.set_preference("security.insecure_field_warning.contextual.enabled", False)
    options.set_capability("acceptInsecureCerts", True)

    # Fix for file downloads (prevents freeze/timeout on non-page content)
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.dir", os.getcwd())
    options.set_preference("browser.helperApps.neverAsk.saveToDisk",
                           "text/plain, application/octet-stream, application/xml, text/csv")
    options.set_preference("browser.download.manager.showWhenStarting", False)

    # Note: Proxy is NOT set here. Proxy is applied on a per-URL basis via driver.get() settings later.

    driver = webdriver.Firefox(options=options)
    driver.implicitly_wait(wait_time)

    return driver

def capture_url_recycled(url, report_dir, proxy_config=None, wait_time=15, render_delay=1.0, verbose=False, network_timeout=10):
    """
    Processes a single URL using a recycled WebDriver instance from the global pool.
    """
    global URL_COUNT_COMPLETED, URL_COUNT_FAILED
    driver = None
    error_summary = "Unknown Error"
    status_code = "N/A"

    # Get driver from pool (blocks until one is available)
    driver = DRIVER_POOL.get()

    # Use requests.Session as a context manager for reliable cleanup of sockets
    with requests.Session() as session:
        temp_html_path = None

        try:
            # 1. Prepare Proxies for requests
            proxies = None
            if proxy_config:
                proxies = {
                    "http": proxy_config,
                    "https": proxy_config,
                }

            # 2. Get HTTP Response Headers using the Session
            response = session.get(url, allow_redirects=True, timeout=network_timeout, proxies=proxies, verify=False)

            final_url = response.url
            headers = dict(response.headers)
            status_code = response.status_code

            # Determine the URL to capture (original or temporary HTML file)
            capture_target = url
            content_type = response.headers.get('Content-Type', '').split(';')[0].strip()

            if content_type in ["text/plain", "application/octet-stream", "application/xml", "text/csv"]:
                # Logic to convert downloadable file content to local HTML for rendering
                temp_content = response.text.replace('<', '&lt;').replace('>', '&gt;')
                html_wrapper = f"""
                <!DOCTYPE html><html><head><title>File Content: {url}</title></head>
                <body><h1>Content from {url}</h1><pre>{temp_content}</pre></body></html>
                """
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html', encoding='utf-8') as tmp_file:
                    tmp_file.write(html_wrapper)
                    temp_html_path = tmp_file.name
                capture_target = f"file://{os.path.abspath(temp_html_path)}"

            # 3. Setup and Navigate WebDriver (Applies proxy if configured)
            # WebDriver already in pool, apply proxy preferences just before navigation
            if proxy_config:
                 # Ensure proxy config is handled for recycled driver if needed,
                 # but for simplicity and reliability, setting profile prefs on pooled drivers is avoided.
                 # Relying only on requests for headers and assuming Firefox's default profile is used for rendering.
                 pass # We rely on 'requests' for proxy status check, and trust the driver for rendering.

            # Set page load timeout based on user input
            driver.set_page_load_timeout(wait_time)

            driver.get(capture_target)

            # --- HYBRID DYNAMIC WAIT + RENDER DELAY ---
            try:
                # Wait for the <body> element to be visible
                WebDriverWait(driver, wait_time).until(
                    EC.visibility_of_element_located((By.TAG_NAME, 'body'))
                )
            except Exception:
                pass

            # Use configurable time for the final mandatory render buffer
            time.sleep(render_delay)
            # ---------------------------------------------------------------------

            # 4. Capture Screenshot
            safe_filename = final_url.replace("://", "_").replace("/", "_").replace(":", "-").replace("?", "__")
            screenshot_path = os.path.join(report_dir, f"{safe_filename}.png")
            driver.save_screenshot(screenshot_path)

            # --- VERBOSE STATUS OUTPUT (SUCCESS) ---
            if verbose:
                print_progress(URL_COUNT_TOTAL)
                status_msg = f"[+] {url} -> SUCCESS ({status_code})"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)
            # ---------------------------------------

            # 5. Store Result (Success)
            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": final_url, "status_code": status_code,
                "screenshot_path": os.path.basename(screenshot_path), "headers": headers
            })

            with COUNTER_LOCK:
                URL_COUNT_COMPLETED += 1

        except (Timeout, ConnectionError, SSLError, ProxyError) as e:
            error_summary = "SSL connection timeout."
            status_code = "TIMEOUT"

            if verbose:
                print_progress(URL_COUNT_TOTAL)
                status_msg = f"[-] {url} -> FAILED ({status_code}) - {error_summary}"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)

            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": url, "status_code": status_code,
                "screenshot_path": "N/A", "headers": {"Error": error_summary}
            })

            with COUNTER_LOCK:
                URL_COUNT_FAILED += 1

        except Exception as e:
            error_type = type(e).__name__
            error_detail = str(e).split('\n')[0]
            error_summary = f"{error_type}: {error_detail}"
            status_code = "ERROR"

            if verbose:
                print_progress(URL_COUNT_TOTAL)
                status_msg = f"[-] {url} -> FAILED ({status_code}) - {error_summary}"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)

            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": url, "status_code": status_code,
                "screenshot_path": "N/A", "headers": {"Error": error_summary}
            })

            with COUNTER_LOCK:
                URL_COUNT_FAILED += 1

        finally:
            # 1. Clean up temporary HTML file if created
            if temp_html_path and os.path.exists(temp_html_path):
                os.remove(temp_html_path)

            # 2. Release driver back to pool
            if driver:
                DRIVER_POOL.put(driver)

            # Ensure progress meter is updated even if verbose is off
            if not verbose:
                print_progress(URL_COUNT_TOTAL)

def generate_html_report(report_dir):
    """Generates the final HTML report file."""
    timestamp_str = time.ctime()

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WappSnap Report - {os.path.basename(report_dir)}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
            th {{ background-color: #f2f2f2; }}
            img {{ max-width: 700px; height: auto; border: 1px solid #ccc; }}
            .headers pre {{ white-space: pre-wrap; word-wrap: break-word; font-size: 0.8em; }}
        </style>
    </head>
    <body>
        <h1>WappSnap Capture Report</h1>
        <p>Report Generated: {timestamp_str}</p>
        <table>
            <thead>
                <tr>
                    <th>Original URL</th>
                    <th>Final URL / Status</th>
                    <th>Screenshot</th>
                    <th>HTTP Response Headers</th>
                </tr>
            </thead>
            <tbody>
    """

    # Add table rows
    for data in GLOBAL_REPORT_DATA:
        header_str = "\n".join([f"{k}: {v}" for k, v in data['headers'].items()])

        row = f"""
        <tr>
            <td><a href="{data['url']}" target="_blank">{data['url']}</a></td>
            <td><strong>{data['final_url']}</strong><br/>Status: {data['status_code']}</td>
            <td>
                {f'<a href="{data["screenshot_path"]}" target="_blank"><img src="{data["screenshot_path"]}" alt="Screenshot"></a>'
                 if data['screenshot_path'] != 'N/A' else 'N/A'}
            </td>
            <td class="headers"><pre>{header_str}</pre></td>
        </tr>
        """
        html_content += row

    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """

    # Save the report
    with open(os.path.join(report_dir, "report.html"), 'w') as f:
        f.write(html_content)

    print(f"\n[+] HTML report generated successfully at {os.path.join(report_dir, 'report.html')}")

# --- Main Logic ---

def main():
    global URL_COUNT_TOTAL
    parser = argparse.ArgumentParser(description="WappSnap: A multi-threaded tool to capture screenshots of web servers.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single URL to capture (e.g., http://example.com).")
    group.add_argument("--file", help="Path to a text file containing URLs (one per line).")
    group.add_argument("--nmap", help="Path to an Nmap XML file to extract HTTP/HTTPS endpoints.")

    parser.add_argument("--proxy", help="Specify a proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050). Default: No proxy.")
    parser.add_argument("--network-timeout", type=int, default=10, help="Maximum seconds to wait for initial HTTP connection/headers (default: 10).")
    parser.add_argument("--wait-time", type=int, default=15, help="Maximum seconds to wait for a page to load/render (default: 15).")
    parser.add_argument("--render-delay", type=float, default=1.0, help="Fixed time (in seconds) to wait after loading, guaranteeing rendering (default: 1.0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity, showing all target URLs and per-request status.")

    parser.add_argument("--threads", type=int, default=MAX_THREADS, help=f"Number of threads to use (default: {MAX_THREADS}).")
    args = parser.parse_args()

    # 1. Prepare Target URLs
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Error: File not found at {args.file}")
            return
    elif args.nmap:
        urls = get_nmap_urls(args.nmap)

    if not urls:
        print("[!] No URLs found to process.")
        return

    print(f"[*] Found {len(urls)} unique URLs to process.")
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}")

    if args.verbose:
        print("\n--- Target URL List ---")
        for u in urls:
            print(f"{u}")
        print("-----------------------\n")

    URL_COUNT_TOTAL = len(urls)
    num_threads = args.threads

    # 2. Initialize the WebDriver Pool
    print(f"[*] Initializing {num_threads} WebDriver instances...")
    for _ in range(num_threads):
        try:
            # Pass wait_time to setup_webdriver to set implicit wait on driver startup
            driver = setup_webdriver(args.wait_time)
            DRIVER_POOL.put(driver)
        except Exception as e:
            print(f"[!] FATAL: Could not initialize WebDriver instance. Check geckodriver/PATH. Error: {e}")
            return

    # 3. Create Report Directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_subdir = f"WappSnap_Run_{timestamp}"
    full_report_path = os.path.join(REPORTS_DIR, report_subdir)
    os.makedirs(full_report_path, exist_ok=True)
    print(f"[*] Report files will be saved in: {full_report_path}")

    # 4. Multi-threaded Processing
    start_time = time.time()

    stop_event = threading.Event()
    def monitor_progress():
        while URL_COUNT_COMPLETED + URL_COUNT_FAILED < URL_COUNT_TOTAL:
            if not args.verbose:
                print_progress(URL_COUNT_TOTAL)
            time.sleep(0.1)
        print_progress(URL_COUNT_TOTAL)

    monitor_thread = threading.Thread(target=monitor_progress)
    monitor_thread.start()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(capture_url_recycled, url, full_report_path,
                                   args.proxy, args.wait_time, args.render_delay,
                                   args.verbose, args.network_timeout) for url in urls]
        for _ in futures: pass # Wait for all to complete

    monitor_thread.join()

    # 5. Cleanup Pool
    print("\n[*] Cleaning up WebDriver pool...")
    while not DRIVER_POOL.empty():
        driver = DRIVER_POOL.get()
        driver.quit()

    end_time = time.time()

    # 6. Generate Final Report
    generate_html_report(full_report_path)

    print(f"\n[*] Total execution time: {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
