<p align="center">
  <pre>
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
    <b>Version 1.7.1</b> by <b>athxsec</b>
  </p>
  <p align="center">
    A feature-rich, 100% open-source subdomain enumeration & reconnaissance tool.
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
* **Active Enumeration:** Brute-force subdomains using a wordlist (`-w`).
* **Live Domain Validation:** Resolves DNS to find live subdomains (`-r`).
* **HTTP/HTTPS Probing:** Checks live subdomains for web servers and extracts titles (`--probe`).
* **CNAME Record Check:** Identifies CNAME records for potential takeover analysis (`--cname`).
* **Wayback Machine URLs:** Fetches historical URLs from Archive.org (`--wayback`).
* **Concurrency Control:** Uses `asyncio.Semaphore` to avoid rate-limiting.
* **Wildcard Detection:** Automatically checks for wildcard domains.
* **Flexible Output:** Save results as `txt` or `json` (`-o`, `-of`).
* **Dual Mode:** Interactive menu or full command-line support.

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

3.  (Optional) Get a good wordlist for the active scan (`-w`).
    * [SecLists - dns-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/dns-Jhaddix.txt)

---

## 💡 Usage

### 1. Interactive Mode (Easy)

For a user-friendly experience, just run the script with no arguments. It will guide you through all the options.

```bash
python3 subseeker_pro.py
```
  </pre>

  <p align="center">
    <b>Version 1.7.1</b> by <b>athxsec</b>
  </p>
  <p align="center">
    A feature-rich, 100% open-source subdomain enumeration & reconnaissance tool.
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
* **Active Enumeration:** Brute-force subdomains using a wordlist (`-w`).
* **Live Domain Validation:** Resolves DNS to find live subdomains (`-r`).
* **HTTP/HTTPS Probing:** Checks live subdomains for web servers and extracts titles (`--probe`).
* **CNAME Record Check:** Identifies CNAME records for potential takeover analysis (`--cname`).
* **Wayback Machine URLs:** Fetches historical URLs from Archive.org (`--wayback`).
* **Concurrency Control:** Uses `asyncio.Semaphore` to avoid rate-limiting.
* **Wildcard Detection:** Automatically checks for wildcard domains.
* **Flexible Output:** Save results as `txt` or `json` (`-o`, `-of`).
* **Dual Mode:** Interactive menu or full command-line support.

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

3.  (Optional) Get a good wordlist for the active scan (`-w`).
    * [SecLists - dns-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/dns-Jhaddix.txt)

---

## 💡 Usage

### 1. Interactive Mode (Easy)

For a user-friendly experience, just run the script with no arguments. It will guide you through all the options.

```bash

python3 subseeker_pro.py
