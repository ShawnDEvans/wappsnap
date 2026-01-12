#!/usr/bin/env python3
import argparse
import os
import time
import requests
import urllib3
from urllib.parse import urlparse
import threading
import queue
import tempfile
from lxml import etree
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.options import Options as ChromeOptions
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
            ip_list = host.xpath('./address[@addrtype="ipv4"]/@addr')
            if not ip_list:
                continue
            ip = ip_list[0]

            for port in host.xpath('./ports/port[state/@state="open"]'):
                port_id = port.get('portid')
                service_name = port.xpath('./service/@name')

                if 'http' in service_name or port_id in ('80', '443', '8080', '8443'):
                    protocol = 'https' if port_id in ('443', '8443') else 'http'
                    urls.add(f"{protocol}://{ip}:{port_id}")
    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
    return list(urls)

def setup_webdriver(wait_time, browser_name, proxy):
    """Initializes a headless WebDriver instance for the pool based on browser_name."""

    if browser_name == "firefox":
        options = FirefoxOptions()
        if proxy:
            socks_parsed = urlparse(proxy)
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.socks", socks_parsed.hostname)
            options.set_preference("network.proxy.socks_port", socks_parsed.port)
            options.set_preference("network.proxy.socks_version", 5)
            options.set_preference("network.proxy.socks_remote_dns", True)
        options.set_preference("webgl.disabled", True)
        options.set_preference("layers.acceleration.disabled", True)
        options.add_argument("-headless")
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

        driver = webdriver.Firefox(options=options)

    elif browser_name == "chrome":
        options = ChromeOptions()
        options.add_argument("--headless=new")
        if proxy:
            options.add_argument(f'--proxy-server={proxy}')
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-software-rasterizer")
        options.add_argument("--force-device-scale-factor=1")
        options.add_argument("--window-size=1280,1024")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")
        options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=options)

    else:
        raise ValueError(f"Unsupported browser: {browser_name}")
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

    network_time = "N/A"
    render_time = "N/A"

    # Get driver from pool (blocks until one is available)
    driver = DRIVER_POOL.get()

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
            start_network = time.time()
            response = session.get(url, allow_redirects=True, timeout=network_timeout, proxies=proxies, verify=False)
            network_time = f"{(time.time() - start_network):.2f}s"

            final_url = response.url
            headers = dict(response.headers)
            status_code = response.status_code

            # Determine the URL to capture (original or temporary HTML file)
            capture_target = url
            screenshot_path_result = "N/A"

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

            # 3. Setup and Navigate WebDriver
            driver.set_page_load_timeout(wait_time)

            start_render = time.time()
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
            render_time = f"{(time.time() - start_render):.2f}s"

            # 4. Capture Screenshot

            # --- FILENAME FIX START ---
            # Truncate the URL at the first '?' to remove query parameters
            filename_base = final_url.split('?')[0]

            # Sanitize the base URL for use as a filename
            safe_filename = filename_base.replace("://", "_").replace("/", "_").replace(":", "-").replace("?", "_").replace("#","")
            # --- FILENAME FIX END ---

            screenshot_path = os.path.join(report_dir, f"{safe_filename}.png")
            driver.save_screenshot(screenshot_path)
            screenshot_path_result = os.path.basename(screenshot_path)

            # --- VERBOSE STATUS OUTPUT (SUCCESS) ---
            if verbose:
                print_progress(URL_COUNT_TOTAL)
                status_msg = f"[+] {url} -> SUCCESS ({status_code}) [N:{network_time} R:{render_time}]"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)
            # ---------------------------------------

            # 5. Store Result (Success)
            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": final_url, "status_code": status_code,
                "screenshot_path": screenshot_path_result, "headers": headers,
                "network_time": network_time, "render_time": render_time
            })

            with COUNTER_LOCK:
                URL_COUNT_COMPLETED += 1

        except (Timeout, ConnectionError, SSLError, ProxyError) as e:
            error_summary = "SSL connection timeout."
            status_code = "TIMEOUT"

            if verbose:
                print_progress(URL_COUNT_TOTAL)
                status_msg = f"[-] {url} -> FAILED ({status_code}) [N:{network_time} R:{render_time}] - {error_summary}"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)

            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": url, "status_code": status_code,
                "screenshot_path": "N/A", "headers": {"Error": error_summary},
                "network_time": network_time, "render_time": render_time
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
                status_msg = f"[-] {url} -> FAILED ({status_code}) [N:{network_time} R:{render_time}] - {error_summary}"
                padded_output = f"\r{status_msg:<{VERBOSITY_LINE_WIDTH}}\n"
                print(padded_output, end='', flush=True)
                print_progress(URL_COUNT_TOTAL)

            GLOBAL_REPORT_DATA.append({
                "url": url, "final_url": url, "status_code": status_code,
                "screenshot_path": "N/A", "headers": {"Error": error_summary},
                "network_time": network_time, "render_time": render_time
            })

            with COUNTER_LOCK:
                URL_COUNT_FAILED += 1

        finally:
            # 1. Clean up temporary HTML file if created
            if temp_html_path and os.path.exists(temp_html_path):
                os.remove(temp_html_path)

            # 2. Release driver back to pool
            if driver:
                try:
                    driver.get("about:blank")
                except Exception:
                    pass
                DRIVER_POOL.put(driver)

            # Ensure progress meter is updated even if verbose is off
            if not verbose:
                print_progress(URL_COUNT_TOTAL)

def generate_html_report(report_dir, report_data):
    """Generates the final HTML report file."""
    timestamp_str = time.ctime()

    # Determine the report title based on filtering
    report_title = "WappSnap Capture Report (Completed Only)" if len(report_data) < URL_COUNT_TOTAL else "WappSnap Capture Report"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WappSnap Report - {os.path.basename(report_dir)}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}

            /* --- Table Layout Settings (CRITICAL) --- */
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                table-layout: fixed; /* Ensures column widths are respected */
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
                vertical-align: top;
                word-wrap: break-word; /* Ensures text wraps */
            }}
            th {{ background-color: #f2f2f2; }}

            /* --- FIXED COLUMN WIDTHS --- */
            /* 1. Original URL */
            th:nth-child(1), td:nth-child(1) {{ width: 20%; }}

            /* 2. Final URL / Status / Times */
            th:nth-child(2), td:nth-child(2) {{
                width: 25%;
            }}

            /* 3. Screenshot */
            th:nth-child(3), td:nth-child(3) {{ width: 35%; }}

            /* 4. HTTP Response Headers */
            th:nth-child(4), td:nth-child(4) {{ width: 20%; }}

            /* --------------------------- */

            img {{ max-width: 100%; height: auto; border: 1px solid #ccc; }}
            .headers pre {{ white-space: pre-wrap; word-wrap: break-word; font-size: 0.8em; }}
        </style>
    </head>
    <body>
        <h1>{report_title}</h1>
        <p>Report Generated: {timestamp_str}</p>
        <p>Total URLs Processed: {URL_COUNT_TOTAL} | Included in Report: {len(report_data)}</p>
        <table>
            <thead>
                <tr>
                    <th>Original URL</th>
                    <th>Final URL / Status / Times</th>
                    <th>Screenshot</th>
                    <th>HTTP Response Headers</th>
                </tr>
            </thead>
            <tbody>
    """

    # Add table rows from the provided report_data list
    for data in report_data:
        header_str = "\n".join([f"{k}: {v}" for k, v in data['headers'].items()])

        net_time = data.get('network_time', 'N/A')
        rend_time = data.get('render_time', 'N/A')

        row = f"""
        <tr>
            <td><a href="{data['url']}" target="_blank">{data['url']}</a></td>
            <td>
                <strong>{data['final_url']}</strong><br/>
                Status: {data['status_code']}<br/>
                Network Time: {net_time}<br/>
                Render Time: {rend_time}
            </td>
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
    report_filename = "report_completed.html" if len(report_data) < URL_COUNT_TOTAL else "report.html"
    report_path = os.path.join(report_dir, report_filename)

    with open(report_path, 'w') as f:
        f.write(html_content)

    print(f"[+] HTML report generated successfully at {report_path}")

# --- Main Logic ---

def main():
    global URL_COUNT_TOTAL, GLOBAL_REPORT_DATA
    parser = argparse.ArgumentParser(description="WappSnap: A multi-threaded tool to capture screenshots of web servers.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to capture (e.g., http://example.com).")
    group.add_argument("-f", "--file", help="Path to a text file containing URLs (one per line).")
    group.add_argument("--nmap", help="Path to an Nmap XML file to extract HTTP/HTTPS endpoints.")

    parser.add_argument("--proxy", help="Specify a proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050). Default: No proxy.")
    parser.add_argument("--network-timeout", type=int, default=10, help="Maximum seconds to wait for initial HTTP connection/headers (default: 10).")
    parser.add_argument("--wait-time", type=int, default=15, help="Maximum seconds to wait for a page to load/render (default: 15).")
    parser.add_argument("--render-delay", type=float, default=1.0, help="Fixed time (in seconds) to wait after loading, guaranteeing rendering (default: 1.0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity, showing all target URLs and per-request status.")
    parser.add_argument("--browser", default="chrome", choices=["chrome", "firefox"],
                        help="Specify the WebDriver browser to use (default: chrome).")

    # NEW: Completed-only report flag
    parser.add_argument("--completed-only", action="store_true",
                        help="Limits the final HTML report to only include URLs that successfully generated a screenshot.")

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
    print(f"[*] Using WebDriver: {args.browser.capitalize()}")

    if args.verbose:
        print("\n--- Target URL List ---")
        for u in urls:
            print(f"{u}")
        print("-----------------------\n")

    URL_COUNT_TOTAL = len(urls)
    num_threads = args.threads if args.threads <= len(urls) else len(urls)

    # 2. Initialize the WebDriver Pool
    print(f"[*] Initializing {num_threads} WebDriver instances...")
    for _ in range(num_threads):
        try:
            driver = setup_webdriver(args.wait_time, args.browser, args.proxy)
            DRIVER_POOL.put(driver)
        except Exception as e:
            print(f"[!] FATAL: Could not initialize {args.browser} WebDriver instance. Check if the required driver is installed and in your PATH. Error: {e}")
            return

    # 3. Create Report Directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_subdir = f"WappSnap_Run_{timestamp}"
    full_report_path = os.path.join(REPORTS_DIR, report_subdir)
    os.makedirs(full_report_path, exist_ok=True)
    print(f"[*] Report files will be saved in: {full_report_path}")

    # 4. Multi-threaded Processing
    start_time = time.time()

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
        try:
            driver.quit()
        except Exception:
            pass

    end_time = time.time()

    # 6. Generate Final Report

    # Filter the report data if the --completed-only flag is set
    report_data_to_use = GLOBAL_REPORT_DATA
    if args.completed_only:
        print(f"[*] Filtering report data: Only including {URL_COUNT_COMPLETED} successful captures...")
        report_data_to_use = [data for data in GLOBAL_REPORT_DATA if data['screenshot_path'] != 'N/A']

    generate_html_report(full_report_path, report_data_to_use) # Pass the filtered list

    print(f"[*] Total execution time: {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
