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

## Help
```
$ ./wappsnap.py -h
usage: 
    wappsnap - Shawn Evans (@IdiotCoderMonkey) (www.nopsec.com)

        Inspired by and based upon:
        PeepingTom - Tim Tomes (@LaNMaSteR53) (www.lanmaster53.com)

    $ python ./wappsnap.py <mode> <path>

options:
  -h, --help    show this help message and exit
  -l LIST_FILE  list input mode. path to list file.
  -x XML_FILE   xml input mode. path to Nessus/Nmap XML file.
  -u TARGET     single input mode. path to target, remote URL or local path.
  -o OUTPUT     output directory
  -t TIMEOUT    socket timeout in seconds. default is 6 seconds.
  --ip-only     use the IP address and ignore the hostname in an Nmap XML file
  -v            verbose mode
  -b            open results in browser

```

## Example Output
```
shawnevans@pop-os:~/tools/wappsnap$ cat flat_file.txt | cut -d '/' -f 3
www.google.com
www.nopsec.com
www.reddit.com
www.amazon.com
fake.effing.wingledong.com
github.com
shawnevans@pop-os:~/tools/wappsnap$ cat flat_file.txt | cut -d '/' -f 3 > hosts.txt
shawnevans@pop-os:~/tools/wappsnap$ sudo nmap -sS -T4 -p 80,443,8443,8080,8081,9090,8090,8888,8088 -iL hosts.txt -oX hosts.xml
shawnevans@pop-os:~/tools/wappsnap$ ./wappsnap.py -x hosts.xml 
[*] Parsed targets:
http://www.google.com:80
https://www.google.com:443
http://www.nopsec.com:80
https://www.nopsec.com:443
http://www.nopsec.com:8080
https://www.nopsec.com:8443
http://www.reddit.com:80
https://www.reddit.com:443
http://www.amazon.com:80
https://www.amazon.com:443
http://github.com:80
https://github.com:443
[*] Analyzing 12 targets.
[*] Storing data in '250605_151316_0787/'
[*] Starting a capture with 7 processes to complete 12 tasks.
[!] Error: connection timeout on http://www.nopsec.com:8080
[!] Error: connection timeout on https://www.nopsec.com:8443
[========================================] 100%
[*] Finished 10 of 12 with 2 errors in 26.02s
```

## HTML Report:

![Sample HTML Report](images/example.png)

