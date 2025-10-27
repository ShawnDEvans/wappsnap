#!/usr/bin/env python3
import argparse
import os
import time
import requests
from requests.exceptions import Timeout, ConnectionError, SSLError, ProxyError
from lxml import etree
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.proxy import Proxy, ProxyType # Required for Selenium Proxy
import urllib3
# --- Warning Suppression ---
# Disable the InsecureRequestWarning that occurs when using verify=False over HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
REPORTS_DIR = "reports"
MAX_THREADS = 8
GLOBAL_REPORT_DATA = []

import threading
URL_COUNT_TOTAL = 0
URL_COUNT_COMPLETED = 0
URL_COUNT_FAILED = 0
COUNTER_LOCK = threading.Lock()


# --- Helper Functions ---
def print_progress(total):
    """Prints the real-time progress meter to the console."""
    # The carriage return '\r' moves the cursor to the start of the line
    print(
        f"⏳ Processing: Total: {total} | Completed: {URL_COUNT_COMPLETED} | Failed: {URL_COUNT_FAILED}",
        end='\r',
        flush=True
    )

def get_nmap_urls(nmap_xml_file):
    """Extracts HTTP/HTTPS URLs from an Nmap XML file."""
    urls = set()
    try:
        tree = etree.parse(nmap_xml_file)
        # XPath to find hosts with open http/https ports
        for host in tree.xpath('//host'):
            ip = host.xpath('./address[@addrtype="ipv4"]/@addr')[0]
            for port in host.xpath('./ports/port[state/@state="open"]'):
                port_id = port.get('portid')
                # Check for common HTTP/HTTPS services
                service_name = port.xpath('./service/@name')
                if 'http' in service_name or port_id in ('80', '443', '8080', '8443'):
                    protocol = 'https' if port_id in ('443', '8443') else 'http'
                    urls.add(f"{protocol}://{ip}:{port_id}")
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
    return list(urls)

def setup_webdriver(proxy_config=None):
    """Initializes a headless Firefox WebDriver, always accepting insecure certificates."""
    options = FirefoxOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,1024")

    # SSL Insecurity is now the default behavior (Always runs)
    options.set_preference("security.mixed_content.block_active_content", False)
    options.set_preference("security.mixed_content.block_display_content", False)
    options.set_preference("security.insecure_field_warning.contextual.enabled", False)
    options.set_capability("acceptInsecureCerts", True)

    # Configure Proxy for Selenium (remains the same as the final SOCKS-fixed version)
    if proxy_config:
        try:
            proxy_type, host_port = proxy_config.split('://', 1)
            host, port = host_port.split(':')
        except ValueError:
            print(f"Warning: Proxy format is invalid for WebDriver: {proxy_config}. Skipping WebDriver proxy.")
            return webdriver.Firefox(options=options)

        options.set_preference("network.proxy.type", 1)

        if 'socks' in proxy_type:
            options.set_preference("network.proxy.socks", host)
            options.set_preference("network.proxy.socks_port", int(port))
            options.set_preference("network.proxy.socks_version", 5)
            options.set_preference("network.proxy.socks_remote_dns", True)

        else:
            options.set_preference("network.proxy.http", host)
            options.set_preference("network.proxy.http_port", int(port))
            options.set_preference("network.proxy.ssl", host)
            options.set_preference("network.proxy.ssl_port", int(port))

    driver = webdriver.Firefox(options=options)
    return driver


def capture_url(url, report_dir, proxy_config=None):
    """Navigates to the URL, captures screenshot, and retrieves headers."""
    global URL_COUNT_COMPLETED, URL_COUNT_FAILED
    driver = None
    error_summary = "Unknown Error"

    try:
        # 1. Prepare Proxies for requests
        proxies = None
        if proxy_config:
            proxies = {
                "http": proxy_config,
                "https": proxy_config,
            }

        # 2. Get HTTP Response Headers using requests
        response = requests.get(url, allow_redirects=True, timeout=10, proxies=proxies, verify=False)

        final_url = response.url
        headers = dict(response.headers)
        status_code = response.status_code

        # 3. Setup and Navigate WebDriver
        driver = setup_webdriver(proxy_config)
        driver.get(url)

        # 4. Capture Screenshot
        safe_filename = final_url.replace("://", "_").replace("/", "_").replace(":", "-").replace("?", "__")
        screenshot_path = os.path.join(report_dir, f"{safe_filename}.png")
        driver.save_screenshot(screenshot_path)

        #print(f"[+] Success: {url} -> {screenshot_path}")

        # 5. Store Result (Success)
        GLOBAL_REPORT_DATA.append({
            "url": url,
            "final_url": final_url,
            "status_code": status_code,
            "screenshot_path": os.path.basename(screenshot_path),
            "headers": headers
        })

        with COUNTER_LOCK:
            URL_COUNT_COMPLETED += 1

    # --- ADDITION EXCEPTION CHECKS HERE (The Fix) ---
    except (Timeout, ConnectionError, SSLError, ProxyError) as e:
        # This block catches most common network failures, including
        # SOCKS/HTTP connection pool errors, which are often classified
        # as a ConnectionError or Timeout/ProxyError internally.
        error_summary = "SSL connection timeout."
        #print(f"[-] Failed to process {url}. Error: {error_summary}")

        # Store Failure
        GLOBAL_REPORT_DATA.append({
            "url": url,
            "final_url": url,
            "status_code": "ERROR",
            "screenshot_path": "N/A",
            "headers": {"Error": error_summary}
        })

        with COUNTER_LOCK:
            URL_COUNT_FAILED += 1

    except Exception as e:
        # Catch all other general exceptions (e.g., WebDriver errors)
        error_type = type(e).__name__
        error_detail = str(e).split('\n')[0]
        error_summary = f"{error_type}: {error_detail}"

        #print(f"[-] Failed to process {url}. Error: {error_summary}")

        # Store Failure
        GLOBAL_REPORT_DATA.append({
            "url": url,
            "final_url": url,
            "status_code": "ERROR",
            "screenshot_path": "N/A",
            "headers": {"Error": error_summary}
        })

        with COUNTER_LOCK:
            URL_COUNT_FAILED += 1
    finally:
        if driver:
            driver.quit()

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

    print(f"\n[+++] HTML report generated successfully at {os.path.join(report_dir, 'report.html')}")

# --- Main Logic ---
def main():
    global URL_COUNT_TOTAL
    parser = argparse.ArgumentParser(description="WappSnap: A multi-threaded tool to capture screenshots of web servers.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single URL to capture (e.g., http://example.com).")
    group.add_argument("--file", help="Path to a text file containing URLs (one per line).")
    group.add_argument("--nmap", help="Path to an Nmap XML file to extract HTTP/HTTPS endpoints.")

    # --- New Proxy Arguments ---
    parser.add_argument("--proxy", help="Specify a proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050). Default: No proxy.")
    # ---------------------------

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
            print(f"Error: File not found at {args.file}")
            return
    elif args.nmap:
        urls = get_nmap_urls(args.nmap)

    if not urls:
        print("No URLs found to process.")
        return

    print(f"Found {len(urls)} unique URLs to process.")
    if args.proxy:
        print(f"Using proxy: {args.proxy}")
    URL_COUNT_TOTAL = len(urls) # Set the total count
    # 2. Create Report Directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_subdir = f"WappSnap_Run_{timestamp}"
    full_report_path = os.path.join(REPORTS_DIR, report_subdir)
    os.makedirs(full_report_path, exist_ok=True)
    print(f"Report files will be saved in: {full_report_path}")

    # 3. Multi-threaded Processing
    start_time = time.time()

    # --- Progress Management ---
    stop_event = threading.Event()

    def monitor_progress():
        while URL_COUNT_COMPLETED + URL_COUNT_FAILED < URL_COUNT_TOTAL:
            print_progress(URL_COUNT_TOTAL)
            time.sleep(0.1) # Update every 100ms
        print_progress(URL_COUNT_TOTAL) # Print final status

    monitor_thread = threading.Thread(target=monitor_progress)
    monitor_thread.start()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Use a lambda function to pass the fixed 'proxy_config' argument to capture_url
        futures = [executor.submit(capture_url, url, full_report_path, args.proxy) for url in urls]
        for _ in futures: pass
    monitor_thread.join() # Wait for the monitor thread to finish
    end_time = time.time()

    # 4. Generate Final Report
    generate_html_report(full_report_path)

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
