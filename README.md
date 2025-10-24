<p align="center">
  <pre>
     █████████             █████      █████████                    █████                                    ███████████                    
    ███░░░░░███           ░░███      ███░░░░░███                  ░░███                                    ░░███░░░░░███                   
   ░███    ░░░  █████ ████ ░███████ ░███    ░░░   ██████   ██████  ░███ █████  ██████  ████████             ░███    ░███ ████████   ██████ 
   ░░█████████ ░░███ ░███  ░███░░███░░█████████  ███░░███ ███░░███ ░███░░███  ███░░███░░███░░███ ██████████ ░██████████ ░░███░░███ ███░░███
    ░░░░░░░░███ ░███ ░███  ░███ ░███ ░░░░░░░░███░███████ ░███████  ░██████░  ░███████  ░███ ░░░ ░░░░░░░░░░  ░███░░░░░░   ░███ ░░░ ░███ ░███
    ███    ░███ ░███ ░███  ░███ ░███ ███    ░███░███░░░  ░███░░░   ░███░░███ ░███░░░   ░███                 ░███         ░███     ░███ ░███
   ░░█████████  ░░████████ ████████ ░░█████████ ░░██████ ░░██████  ████ █████░░██████  █████                █████        █████    ░░██████ 
    ░░░░░░░░░    ░░░░░░░░ ░░░░░░░░   ░░░░░░░░░   ░░░░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░                ░░░░░        ░░░░░      ░░░░░░  
                                                                                                                                           
                                                                                                                                           
                                                                                                                                           
  </pre>
  <p align="center">
    <b>Version 1.6.0</b> by <b>athxsec</b>
  </p>
  <p align="center">
    A high-speed, 100% open-source subdomain enumeration tool with active validation.
  </p>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.7+-blue.svg?style=for-the-badge&logo=python">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge">
  <img alt="Open Source" src="https://img.shields.io/badge/Open%20Source-Yes-brightgreen.svg?style=for-the-badge">
</p>

![Demo of SubSeeker-Pro](./demo.gif)

---

## 🚀 Key Features

* **100% Open Source:** No API keys required.
* **Passive Enumeration:** Gathers subdomains from reliable sources (`crt.sh`, `AlienVault`).
* **Active Enumeration:** Brute-force subdomains with a high-speed, asynchronous DNS resolver.
* **Live Domain Validation:** A dedicated **`--resolve`** mode to filter a large list down to only the subdomains that are currently live.
* **Concurrency Control:** Uses `asyncio.Semaphore` to avoid rate-limiting and errors.
* **Wildcard Detection:** Automatically checks for and warns about wildcard domains.
* **Dual Mode:**
    * **Interactive:** A beautiful, user-friendly menu for beginners.
    * **CLI:** Full command-line support for automation and advanced users.

---

## 🔧 Installation

1.  Clone the repository:
    ```bash
    git clone [https://github.com/athxsec/SubSeeker-Pro.git](https://github.com/athxsec/SubSeeker-Pro.git)
    cd SubSeeker-Pro
    ```

2.  Install the required Python libraries:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Optional) Get a good wordlist for the active scan.
    * [SecLists - dns-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/dns-Jhaddix.txt)

---

## 💡 Usage

You can run the tool in two ways:

### 1. Interactive Mode (Easy)

For a user-friendly experience, just run the script with no arguments.

```bash
python3 subseeker_pro.py
```

###Command-Line Mode (Advanced)
***usage: 
```
 subseeker_pro.py [-h] -d DOMAIN [-w WORDLIST] [-t THREADS] [-o OUTPUT]
                        [-r] [--no-passive] [--no-active] [--no-wildcard]
                        [-c CONCURRENCY]
```
SubSeeker-Pro 1.6.0 by athxsec - A powerful asyncio-based subdomain finder.

options: 
```
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        The target domain (e.g., google.com)
  -w WORDLIST, --wordlist WORDLIST
                        Path to the wordlist file for active scan
  -t THREADS, --threads THREADS
                        Number of concurrent workers for active/resolve scan
                        (default: 100)
  -o OUTPUT, --output OUTPUT
                        Path to the output file to save results (shows all
                        results, or only resolved if -r is used)
  -r, --resolve         Resolve all found subdomains and show only live ones
  --no-passive          Skip all passive scans
  --no-active           Skip the active (brute-force) scan
  --no-wildcard         Skip the wildcard detection
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent passive scans (default: 2)
```
                      
Examples:

Passive scan only:

```Bash
python3 subseeker_pro.py -d example.com
Passive scan + Resolve (Show only LIVE subdomains):
```
```Bash
python3 subseeker_pro.py -d example.com --resolve
Full Scan (Passive + Active) and Save LIVE results:
```
```Bash
python3 subseeker_pro.py -d example.com -w wordlist.txt -r -o robu_live_subs.txt
```

Dance Mode
dance mode in 1

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.
