# WappSnap

WebSnapp is a handy web application screen shot utility. It can ingest Nessus/Nmap XML, flat text files, or a single URL on the command line. 


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
