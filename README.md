# WappSnap

WappSnap is a handy web application screen shot utility. It can ingest Nessus/Nmap XML, flat text files, or a single URL on the command line. 


> **Note**
> WappSnap was inspired by and based upon PeepingTom. I relied on PeepingTom for many years. Out of necessicity I had to make my own updates to keep it working. Over time these changes resulted in a tool that deserved its own repo. It would not be here without PeepingTom.
>
> OG: https://bitbucket.org/LaNMaSteR53/peepingtom/
> Thanks @LaNMaSteR53

## Installation

```bash
$ git clone https://github.com/ShawnDEvans/wappsnap
$ cd wappsnap
$ python3 -m pip install -r requirements.txt
$ ./wappsnap.py -h
...
```

## Features:
- Extract targets from Nessus and Nmap
- Flat text files
- Generates an HTML report

## Plans:
- Add a JSON output option 
- Add option to change output resolution

## Help
```
$ python3 tmp.py -h
usage: tmp.py [-h] (-u URL | -f FILE | --nmap NMAP) [--proxy PROXY] [--network-timeout NETWORK_TIMEOUT] [--wait-time WAIT_TIME]
              [--render-delay RENDER_DELAY] [-v] [--browser {chrome,firefox}] [--completed-only] [--threads THREADS]

WappSnap: A multi-threaded tool to capture screenshots of web servers.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Single URL to capture (e.g., http://example.com).
  -f FILE, --file FILE  Path to a text file containing URLs (one per line).
  --nmap NMAP           Path to an Nmap XML file to extract HTTP/HTTPS endpoints.
  --proxy PROXY         Specify a proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050). Default: No proxy.
  --network-timeout NETWORK_TIMEOUT
                        Maximum seconds to wait for initial HTTP connection/headers (default: 10).
  --wait-time WAIT_TIME
                        Maximum seconds to wait for a page to load/render (default: 15).
  --render-delay RENDER_DELAY
                        Fixed time (in seconds) to wait after loading, guaranteeing rendering (default: 1.0).
  -v, --verbose         Increase output verbosity, showing all target URLs and per-request status.
  --browser {chrome,firefox}
                        Specify the WebDriver browser to use (default: chrome).
  --completed-only      Limits the final HTML report to only include URLs that successfully generated a screenshot.
  --threads THREADS     Number of threads to use (default: 8).

```

## Example Output
```
$ ./wappsnap.py -f urls.txt --completed-only
[*] Found 218 unique URLs to process.
[*] Using WebDriver: Chrome
[*] Initializing 8 WebDriver instances...
[*] Report files will be saved in: reports/WappSnap_Run_20251203_173052
[*] ⏳ Processing: Total: 218 | Completed: 66 | Failed: 152
[*] Cleaning up WebDriver pool...
[*] Filtering report data: Only including 66 successful captures...
[+] HTML report generated successfully at reports/WappSnap_Run_20251203_173052/report_completed.html
[*] Total execution time: 85.77 seconds.

```

## HTML Report:

![Sample HTML Report](images/example.png)

