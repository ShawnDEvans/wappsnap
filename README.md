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
- Add option to control page the load wait time (not the same as timeout)
- Add setting to control the number of threads
- Proper threading vs multiprocessing.Pool()
- Add option to change output resolution

## Help
```
$ ./wappsnap.py -h
usage: wappsnap.py [-h] (--url URL | --file FILE | --nmap NMAP) [--proxy PROXY] [--wait-time WAIT_TIME] [--threads THREADS] [--render-delay RENDER_DELAY]

WappSnap: A multi-threaded tool to capture screenshots of web servers.

options:
  -h, --help            show this help message and exit
  --url URL             Single URL to capture (e.g., http://example.com).
  --file FILE           Path to a text file containing URLs (one per line).
  --nmap NMAP           Path to an Nmap XML file to extract HTTP/HTTPS endpoints.
  --proxy PROXY         Specify a proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050). Default: No proxy.
  --wait-time WAIT_TIME
                        Maximum seconds to wait for a connection (default: 15).
  --threads THREADS     Number of threads to use (default: 20).
  --render-delay RENDER_DELAY
                        Fixed time (in seconds) to wait after loading, guaranteeing rendering (default: 3.0).

```

## Example Output
```
$ ./wappsnap.py --proxy socks5://127.0.0.1:1082 --nmap nmap-sS-sC-sV-top-300-open.xml 
Found 113 unique URLs to process.
Using proxy: socks5://127.0.0.1:1082
Report files will be saved in: reports/WappSnap_Run_20251028_134440
⏳ Processing: Total: 113 | Completed: 102 | Failed: 11
[+++] HTML report generated successfully at reports/WappSnap_Run_20251028_134440/report.html

Total execution time: 248.59 seconds.
```

## HTML Report:

![Sample HTML Report](images/example.png)

