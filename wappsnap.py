#!/usr/bin/env python

import sys, traceback
import subprocess
import re
import time
import os
import hashlib
import requests
import random
import multiprocessing
from optparse import OptionParser
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.support.wait import WebDriverWait
from selenium.common.exceptions import *

FIREFOX_PATH = '/usr/bin/firefox'
WINDOW_SIZE = "1024,768"

#=================================================
# MAIN FUNCTION
#=================================================

def main():
    # depenency check
    #if not all([os.path.exists('/usr/local/bin/phantomjs'), os.path.exists('/usr/bin/curl')]):
    #    print('[!] PhantomJS and cURL required.')
    #    return
    # parse options
    import argparse
    usage = """
    WappSnap - Shawn Evans (@IdiotCoderMonkey) (sevans@nopsec.com)

    Inspired by and based upon:
        PeepingTom - Tim Tomes (@LaNMaSteR53) (www.lanmaster53.com)
    """
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('-l', help='list input mode. path to list file.', dest='list_file', action='store')
    parser.add_argument('-x', help='xml input mode. path to Nessus/Nmap XML file.', dest='xml_file', action='store')
    parser.add_argument('-u', help='single input mode. path to target, remote URL or local path.', dest='target', action='store')
    parser.add_argument('-o', help='output directory', dest='output', action='store')
    parser.add_argument('-t', help='socket timeout in seconds. default is 6 seconds.', dest='timeout', type=int, action='store')
    parser.add_argument('--ip-only', help='use the IP address and ignore the hostname in an Nmap XML file', dest='iponly', default=False, action='store_true')
    parser.add_argument('-v', help='verbose mode', dest='verbose', action='store_true', default=False)
    parser.add_argument('-b', help='open results in browser', dest='browser', action='store_true', default=False)
    #parser.add_argument('--proxy', help='Configure a SOCKS or HTTP proxy, socks:// or http://, ex -p socks://localhost:1082', dest='proxy', action='store')
    opts = parser.parse_args()

    # process options
    # input source
    if opts.list_file:
        try:
            targets = open(opts.list_file).read().split()
        except IOError:
            print('[!] Invalid path to list file: \'%s\'' % opts.list_file)
            return
    elif opts.xml_file:
        # optimized portion of Peeper (https://github.com/invisiblethreat/peeper) by Scott Walsh (@blacktip)
        import xml.etree.ElementTree as ET
        try: tree = ET.parse(opts.xml_file)
        except IOError:
            print('[!] Invalid path to XML file: \'%s\'' % opts.xml_file)
            return
        except ET.ParseError as e:
            print('[!] Not a valid XML file: \'%s\'' % opts.xml_file)
            print(e)
            return
        root = tree.getroot()
        if root.tag.lower() == 'nmaprun':
            # parse nmap file
            targets = parse_nmap(root, opts.iponly)
        elif root.tag.lower() == 'nessusclientdata_v2':
            # parse nessus file
            targets = parse_nessus(root)
        print('[*] Parsed targets:')
        for x in targets: print(x)
    elif opts.target:
        targets = [opts.target]
    else:
        print('[!] Input mode required.')
        return
    # storage location
    if opts.output:
        directory = opts.output
        if os.path.isdir(directory):
            print('[!] Output directory already exists: \'%s\'' % directory)
            return
    else:
        random.seed()
        directory = time.strftime('%y%m%d_%H%M%S', time.localtime()) + '_%04d' % random.randint(1, 10000)
    # connection timeout
    timeout = opts.timeout if opts.timeout else 6

    print('[*] Analyzing %d targets.' % (len(targets)))
    print('[*] Storing data in \'%s/\'' % (directory))
    os.mkdir(directory)
    report = 'wappsnap.html'
    outfile = '%s/%s' % (directory, report)

    # logic to gather screenshots and headers for the given targets
    db = {'targets': []}
    cnt = 0
    tot = len(targets) * 2
    try:
        # Create a Manager to handle shared objects across processes
        with multiprocessing.Manager() as manager:
            # Create a shared integer value initialized to 0
            completed_tasks_count = manager.Value('i', 0) # 'i' for integer
            error_tasks_count = manager.Value('i', 0) # 'i' for integer
            # initialize the targets for the processing pool
            target_processing_data = [
                (target, directory, timeout, completed_tasks_count, error_tasks_count)
                for target in targets
            ]
            num_tasks = len(target_processing_data)
            num_processes = multiprocessing.cpu_count()
            print(f"[*] Starting a capture with {num_processes} processes to complete {num_tasks} tasks.")
            with multiprocessing.Pool(processes=num_processes) as capture_pool:
                async_result = capture_pool.starmap_async(process_target, target_processing_data)
                start_time = time.time()
                while not async_result.ready(): # Check if all tasks are done
                    time.sleep(2) # Wait a bit before checking again
                    current_completed = completed_tasks_count.value
                    failed_tasks = error_tasks_count.value
                    print_progress(current_completed+failed_tasks, len(targets))
                    elapsed_time = time.time() - start_time
                    #print(f"[*] Main process: {current_completed}/{num_tasks} tasks completed. Elapsed: {elapsed_time:.2f}s")
                db['targets'] = async_result.get()
                final_completed = completed_tasks_count.value
                final_error = error_tasks_count.value
                print(f"\n[*] Finished {final_completed} of {num_tasks} with {final_error} errors in {elapsed_time:.2f}s")
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        line_number = traceback.extract_tb(exc_traceback)[-1][1]
        print(f"[!] Error: {e} on line {line_number}")
        print('[!] %s' % (e.__str__()))

    # build the report and exit
    build_report(db, outfile)
    if opts.browser:
        import webbrowser
        path = os.getcwd()
        w = webbrowser.get()
        w.open('file://%s/%s/%s' % (path, directory, report))
    print('[*] Done.')

#=================================================
# SUPPORT FUNCTIONS
#=================================================

def initialize_driver():
    pass

def process_target(target, directory, timeout, shared_counter, error_counter):
    #print('[*]',f'Capturing {target}')
    options = FirefoxOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-features=WebContentsForceDark")
    options.add_argument("--disable-features=DarkMode")
    options.add_argument('log-level=3')
    #options.set_preference('network.proxy.type', 1)
    #options.set_preference('network.proxy.socks', '127.0.0.1')
    #options.set_preference('network.proxy.socks_port', 1082)
    #options.set_preference('network.proxy.socks_remote_dns', True)
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--window-size=%s" % WINDOW_SIZE)
    service = webdriver.FirefoxService()
    driver = webdriver.Firefox(service=service, options=options)
    dx, dy = driver.execute_script("var w=window; return [w.outerWidth - w.innerWidth, w.outerHeight - w.innerHeight];")
    driver.set_window_size(1024+dx, 768+dy)
    driver.set_page_load_timeout(timeout)
    try:
        # Displays the target name to the right of the progress bar
        imgname = '{}.png'.format(re.sub('\W','',target))
        srcname = '{}.txt'.format(re.sub('\W','',target))
        imgpath = '{}/{}'.format(directory, imgname)
        srcpath = '{}/{}'.format(directory, srcname)
        target_data = {}
        target_data['hash'] = hashlib.md5(open(imgpath, 'rb').read()).hexdigest() if os.path.exists(imgpath) else 'z'*32
        target_data['url'] = target
        target_data['imgpath'] = imgname
        target_data['srcpath'] = srcname
        driver.get(target)
        target_data['headers'] = get_headers(target)
        time.sleep(.5)
        htmlsrc = driver.page_source
        with open(srcpath, 'w') as f: f.write(htmlsrc)
        driver.save_screenshot(imgpath)
        shared_counter.value += 1
        driver.quit()
        return target_data
    except TimeoutException as e:
        print('[!]', f'Error: connection timeout on {target}')
        error_counter.value += 1
        return target_data
    except WebDriverException as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        line_number = traceback.extract_tb(exc_traceback)[-1][1]
        print('[!]', f'Error: unkown error while connecting to {target}')
        error_counter.value += 1
        return target_data

def parse_nmap(root, iponly):
    http_ports = [80,8000,8080,8081,8082,8888,8088]
    https_ports = [443,8443,4433,9090,1443,10000,4444,9000]
    targets = []
    # iterate through all host nodes
    for host in root.iter('host'):
        hostname = host.find('address').get('addr')
        # hostname node doesn't always exist. when it does, overwrite address previously assigned to hostanme
        if not iponly:
            hostname_node = host.find('hostnames').find('hostname')
            if hostname_node is not None: hostname = hostname_node.get('name')
        # iterate through all port nodes reported for the current host
        for item in host.iter('port'):
            state = item.find('state').get('state')
            if state.lower() == 'open':
                # service node doesn't always exist when a port is open
                service = item.find('service').get('name') if item.find('service') is not None else ''
                port = item.get('portid')
                if 'http' in service.lower() or int(port) in (http_ports + https_ports):
                    proto = 'http'
                    if 'https' in service.lower() or int(port) in https_ports:
                        proto = 'https'
                    url = '%s://%s:%s' % (proto, hostname, port)
                    if not url in targets:
                        targets.append(url)
                elif not service:
                    # show the host and port for unknown services
                    print('[-] Unknown service: %s:%s' % (hostname, port))
    return targets

def parse_nessus(root):
    targets = []
    for host in root.iter('ReportHost'):
        name = host.get('name')
        for item in host.iter('ReportItem'):
            svc = item.get('svc_name')
            plugname = item.get('pluginName')
            if (svc in ['www','http?','https?'] and plugname.lower().startswith('service detection')):
                port = item.get('port')
                output = item.find('plugin_output').text.strip()
                proto = guessProto(output)
                url = '%s://%s:%s' % (proto, name, port)
                if not url in targets:
                    targets.append(url)
    return targets

def guessProto(output):
    secure = re.search('TLS|SSL|tls|ssl|https', output)
    if secure:
        return "https"
    return "http"

def get_headers(url):
    try:
        # Send an HTTP GET request to the specified URL
        # The 'timeout' parameter is good practice to prevent the request from hanging indefinitely.
        headers = {}
        headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0'
        response = requests.get(url, timeout=10, verify=False, headers=headers)

        # Raise an HTTPError for bad responses (4xx or 5xx)
        # response.raise_for_status()

        # The .headers attribute of the response object contains a dictionary-like
        # object of the response headers.
        headers = response.headers
        return '\n'.join(list(map(lambda item: f'{item[0]}: {item[1]}' if item else '', headers.items())))

    except requests.exceptions.HTTPError as errh:
        print('[!]', f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print('[!]', f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print('[!]', f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print('[!]', f"An unexpected error occurred: {err}")
    return 'Error'

def print_progress(cnt, tot):
    percent = 100 * float(cnt) / float(tot)
    #if target and previouslen > len(target):
    #    target = target + ' ' * (previouslen - len(target))
    sys.stdout.write('[%-40s] %d%%\r' % ('='*int(float(percent)/100*40), percent))
    sys.stdout.flush()
    return ''

def build_report(db, outfile):
    live_markup = ''
    error_markup = ''
    dead_markup = ''
    # process markup for live targets
    for live in sorted(db['targets'], key=lambda k: k['hash']):
        imgpath = live.get('imgpath')
        url = live.get('url')
        srcpath = live.get('srcpath')
        headers = live.get('headers')
        live_markup += f"<tr><td class='img'><a href='{imgpath}' target='_blank'><img src='{imgpath}' onerror=\"this.parentNode.parentNode.innerHTML='No image available.';\" /></a></td><td class='head'><a href='{url}' target='_blank'>{url}</a> (<a href='{srcpath}' target='_blank'>source</a>)<br /><pre>{headers}</pre></td></tr>\n"
    # add markup to the report
    file = open(outfile, 'w')
    file.write("""
<!doctype html>
<head>
<style>
table, td, th {border: 1px solid black;border-collapse: collapse;padding: 5px;font-size: .9em;font-family: tahoma;}
table {width: 100%%;table-layout: fixed;min-width: 1000px;}
td.img {width: 40%%;}
img {width: 100%%;}
td.head {vertical-align: top;word-wrap: break-word;}
</style>
</head>
<body>
<table>
%s
</table>
</body>
</html>""" % (live_markup))
    file.close()

#=================================================
# START
#=================================================

if __name__ == "__main__": main()
