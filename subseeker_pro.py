#!/usr/bin/env python3
#
# Tool:     SubSeeker-Pro
# Author:   athxsec
# Version:  1.7.1 (Wayback Fix Edition)
#
# A high-speed, asyncio-based subdomain enumeration tool
# with interactive and command-line modes. Includes probing, CNAME checks,
# Wayback URLs, IP info, and JSON output. All open-source.
#
# NEW in 1.7.1:
# - Fixed "Session is closed" error for Wayback Machine queries.
#

import argparse
import asyncio
import aiohttp
import aiodns
import re
import sys
import random
import json
import ipaddress
from types import SimpleNamespace
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table

# --- Metadata ---
__author__ = "athxsec"
__version__ = "1.7.1" # Incremented version

# Initialize rich console
console = Console()

# --- Global Data Structures ---
results_data = {}

# --- Configuration ---
RESOLVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 SubSeekerPro"
SESSION_TIMEOUT = aiohttp.ClientTimeout(total=25)
DEFAULT_PASSIVE_CONCURRENCY = 2
DEFAULT_RESOLVE_THREADS = 100
DEFAULT_PROBE_CONCURRENCY = 50
TITLE_REGEX = re.compile(r'<title.*?>(.*?)</title>', re.IGNORECASE | re.DOTALL)

# --- Utility Functions ---

def is_valid_domain(value):
    """ Basic domain validation """
    if not value or '.' not in value:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid domain.")
    return value.lower()

def print_result(subdomain, data, args):
    """ Prints a single result line based on collected data """
    # Don't print detailed lines if only doing basic discovery
    if not args.resolve and not args.probe and not args.cname and not args.wayback:
        console.print(f"[+] Found: [bold green]{subdomain}[/]", highlight=False)
        return

    output = f"[+] [bold green]{subdomain}[/]"
    details = []
    if data.get("ips"):
        details.append(f"IPs: [cyan]{', '.join(data['ips'])}[/]")
    if args.cname and data.get("cnames"):
        details.append(f"CNAMEs: [yellow]{', '.join(data['cnames'])}[/]")
    if args.probe and data.get("http_urls"):
        urls_str = ', '.join(f"[link={url}]{url}[/link]" for url in data['http_urls'])
        details.append(f"Web: {urls_str}")
        if data.get("title"):
            title = data['title'].strip()
            title = title[:60] + '...' if len(title) > 63 else title
            details.append(f"Title: [dim italic]'{title}'[/]")
    if args.wayback and data.get("wayback"):
        details.append(f"Wayback: [blue]{len(data['wayback'])} URLs[/]")

    if details:
        output += f" ({'; '.join(details)})"
    console.print(output, highlight=False)

# --- Wildcard DNS Detection (Created by athxsec) ---

async def check_wildcard(domain: str) -> bool:
    """ Detect wildcard DNS """
    console.print(f"[*] Checking for wildcard DNS on [bold cyan]{domain}[/]...", style="yellow")
    test_sub = f"{random.randint(10000,99999)}-subseeker-test.{domain}" # More unique name
    resolver = aiodns.DNSResolver()
    resolver.nameservers = RESOLVERS
    try:
        await resolver.query(test_sub, 'A')
        console.print(f"[!] [bold red]Wildcard DNS detected on {domain}. Results may include false positives.[/]", style="red")
        return True
    except aiodns.error.DNSError:
        console.print(f"[*] No wildcard DNS detected for {domain}.", style="dim")
        return False
    except Exception as e:
        console.print(f"[-] Wildcard check error for {domain}: {e}", style="dim")
        return False # Assume no wildcard if check fails

# --- DNS Resolution & CNAME Engine (Modified by athxsec) ---

async def resolve_worker(domain_queue: asyncio.Queue, resolver: aiodns.DNSResolver, check_cname: bool):
    """ Worker task for resolving A and optionally CNAME records. """
    while True:
        try:
            domain = await domain_queue.get()
            ips = set()
            cnames = set()
            is_live = False

            try:
                a_records = await resolver.query(domain, 'A')
                ips.update(record.host for record in a_records)
                is_live = True
            except (aiodns.error.DNSError, asyncio.TimeoutError): pass

            if check_cname:
                try:
                    cname_records = await resolver.query(domain, 'CNAME')
                    cnames.update(record.cname for record in cname_records)
                    is_live = True # Consider live if CNAME exists
                except (aiodns.error.DNSError, asyncio.TimeoutError): pass

            if is_live:
                if domain not in results_data: results_data[domain] = {}
                results_data[domain]["ips"] = sorted(list(ips))
                results_data[domain]["cnames"] = sorted(list(cnames))

            domain_queue.task_done()
        except asyncio.CancelledError: break
        except Exception as e:
            console.print(f"[-] Resolver error for {domain}: {e}", style="dim")
            domain_queue.task_done()

async def run_resolver_engine(domains_to_check: set, num_threads: int, check_cname: bool):
    """ High-speed DNS resolver """
    domain_queue = asyncio.Queue()
    for domain in domains_to_check: domain_queue.put_nowait(domain)
    if domain_queue.empty(): return

    resolver = aiodns.DNSResolver()
    resolver.nameservers = RESOLVERS
    workers = [asyncio.create_task(resolve_worker(domain_queue, resolver, check_cname)) for _ in range(num_threads)]
    await domain_queue.join()
    for worker in workers: worker.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

# --- HTTP/HTTPS Probing Engine (Created by athxsec) ---

async def probe_worker(domain_queue: asyncio.Queue, session: aiohttp.ClientSession):
    """ Worker task for probing HTTP/HTTPS endpoints """
    while True:
        try:
            domain = await domain_queue.get()
            found_urls = []
            title = ""
            for scheme in ["https", "http"]:
                url = f"{scheme}://{domain}"
                try:
                    async with session.head(url, timeout=SESSION_TIMEOUT, allow_redirects=True) as response:
                        if 200 <= response.status < 400:
                            final_url = str(response.url)
                            found_urls.append(final_url)
                            if scheme == "https" and not title and final_url.startswith("https"): # Prioritize title from final https URL
                                try:
                                    async with session.get(final_url, timeout=SESSION_TIMEOUT) as get_response:
                                        if 200 <= get_response.status < 300:
                                            html_chunk = await get_response.content.read(1024 * 32) # Read 32KB
                                            match = TITLE_REGEX.search(html_chunk.decode(get_response.charset or 'utf-8', errors='ignore'))
                                            if match: title = match.group(1).strip().replace('\n', ' ').replace('\r', '')
                                except Exception: pass # Ignore GET errors
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError): pass
                except Exception as e: console.print(f"[-] Probe error for {url}: {e}", style="dim")

            if found_urls:
                if domain not in results_data: results_data[domain] = {}
                results_data[domain]["http_urls"] = sorted(list(set(found_urls)))
                results_data[domain]["title"] = title
            domain_queue.task_done()
        except asyncio.CancelledError: break
        except Exception: domain_queue.task_done()

async def run_probing_engine(domains_to_probe: set, num_threads: int):
    """ Runs the HTTP/HTTPS probing """
    domain_queue = asyncio.Queue()
    for domain in domains_to_probe: domain_queue.put_nowait(domain)
    if domain_queue.empty(): return

    resolver = aiohttp.AsyncResolver(nameservers=RESOLVERS)
    connector = aiohttp.TCPConnector(resolver=resolver, ssl=False, limit_per_host=num_threads)
    headers = {'User-Agent': USER_AGENT}
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        workers = [asyncio.create_task(probe_worker(domain_queue, session)) for _ in range(num_threads)]
        await domain_queue.join()
        for worker in workers: worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

# --- Wayback Machine Engine (Created by athxsec) ---

async def source_wayback(domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
    """ Get historical URLs from the Wayback Machine """
    async with semaphore:
        # console.print(f"[*] Querying Wayback Machine for {domain}...", style="dim") # Can be noisy
        wayback_urls = set()
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=1000"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if len(data) > 1: # Check if there are actual results beyond the header
                             wayback_urls.update(item[0] for item in data[1:])
                    except (json.JSONDecodeError, aiohttp.ContentTypeError): pass
                # Don't print errors for Wayback, it's often noisy/flaky
                # else: console.print(f"[-] Wayback error for {domain}: Status {response.status}", style="red")

            if wayback_urls:
                if domain not in results_data: results_data[domain] = {}
                results_data[domain]["wayback"] = sorted(list(wayback_urls))
        except asyncio.TimeoutError: pass # Ignore timeouts for Wayback
        except Exception as e: console.print(f"[-] Wayback error for {domain}: {e}", style="dim") # Print other errors

# --- Passive Sources (Modified by athxsec) ---

async def source_crtsh(domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, found_passive_subs: set):
    """ Get subdomains from crt.sh """
    async with semaphore:
        console.print("[*] Querying crt.sh...", style="dim")
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=SESSION_TIMEOUT) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '').strip()
                            if name_value:
                                subs = name_value.split('\n')
                                for sub in subs:
                                    sub_clean = sub.strip().lower()
                                    # Ensure it's a subdomain and not the base domain itself
                                    if sub_clean.endswith(f".{domain}") and sub_clean != domain and '*' not in sub_clean:
                                        found_passive_subs.add(sub_clean)
                    except aiohttp.ContentTypeError: pass
                else: console.print(f"[-] crt.sh error: Status {response.status}", style="red")
        except asyncio.TimeoutError: console.print(f"[-] crt.sh error: Timeout", style="red")
        except Exception as e: console.print(f"[-] crt.sh error: {e}", style="dim")

async def source_alienvault(domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, found_passive_subs: set):
    """ Get subdomains from AlienVault OTX """
    async with semaphore:
        console.print("[*] Querying AlienVault OTX...", style="dim")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            async with session.get(url, timeout=SESSION_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '').strip().lower()
                        if hostname.endswith(f".{domain}") and hostname != domain and '*' not in hostname:
                            found_passive_subs.add(hostname)
                # Don't print 429 rate limit errors, they are expected
                elif response.status != 429: console.print(f"[-] AlienVault error: Status {response.status}", style="red")
        except asyncio.TimeoutError: console.print(f"[-] AlienVault error: Timeout", style="red")
        except Exception as e: console.print(f"[-] AlienVault error: {e}", style="dim")

# --- Active Brute-force (Modified by athxsec) ---

async def active_scan(domain: str, wordlist_file: str, num_threads: int, found_active_subs: set):
    """ Actively brute-force subdomains """
    console.print(f"[*] Starting active scan with {num_threads} workers...", style="yellow")
    domains_to_check = set()
    try:
        with open(wordlist_file, 'r') as f:
            for line in f:
                word = line.strip()
                if word: domains_to_check.add(f"{word}.{domain}")
    except FileNotFoundError: console.print(f"[-] Wordlist not found: {wordlist_file}", style="red"); return
    if not domains_to_check: console.print("[-] Wordlist is empty.", style="red"); return

    console.print(f"[*] Loaded {len(domains_to_check)} candidates for active scan.", style="yellow")
    # Run resolver, save directly to the provided set (found_active_subs)
    # Use check_cname=False because we only care if it resolves for brute-force confirmation
    await run_resolver_engine(domains_to_check, num_threads, check_cname=False)
    # Add resolved domains to the output set
    found_active_subs.update(results_data.keys() & domains_to_check)


# --- Argument Parsing & Interactive Mode ---

def get_cli_args():
    """ Parse command-line arguments """
    parser = argparse.ArgumentParser(
        description=f"SubSeeker-Pro {__version__} by {__author__} - Feature-rich subdomain finder.",
        epilog="Example: python3 subseeker_pro.py -d example.com -r --probe --cname --wayback -o results.json -of json"
    )
    parser.add_argument("-d", "--domain", type=is_valid_domain, help="The target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for active brute-force scan")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_RESOLVE_THREADS, help=f"DNS resolve/active scan threads (default: {DEFAULT_RESOLVE_THREADS})")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-of", "--output-format", choices=['txt', 'json'], default='txt', help="Output file format (default: txt)")
    parser.add_argument("-r", "--resolve", action="store_true", help="Resolve all found subdomains to find live ones")
    parser.add_argument("--probe", action="store_true", help="Probe resolved domains for HTTP/HTTPS servers and titles")
    parser.add_argument("--cname", action="store_true", help="Check for CNAME records during resolution")
    parser.add_argument("--wayback", action="store_true", help="Query Wayback Machine for URLs on resolved/probed domains")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive enumeration sources")
    parser.add_argument("--no-active", action="store_true", help="Skip active brute-force scan")
    parser.add_argument("--no-wildcard", action="store_true", help="Skip wildcard DNS check")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_PASSIVE_CONCURRENCY, help=f"Concurrent passive source queries (default: {DEFAULT_PASSIVE_CONCURRENCY})")
    parser.add_argument("--probe-concurrency", type=int, default=DEFAULT_PROBE_CONCURRENCY, help=f"Concurrent HTTP probes (default: {DEFAULT_PROBE_CONCURRENCY})")
    return parser.parse_args()

def print_banners():
    """ Prints the main ASCII art banners """
    console.print(r"""
      █████████               █████       █████████                      █████                                        ███████████           
     ███░░░░░███              ░░███       ███░░░░░███                    ░░███                                       ░░███░░░░░███          
    ░███     ░░░  █████  ████  ░███████ ░███     ░░░    ██████    ██████  ░███ █████  ██████     ████████             ░███    ░███   ████████   ██████ 
    ░░█████████  ░░███  ░███   ░███░░███ ░░█████████   ███░░███ ███░░███  ░███░░███  ███░░███░  ░███░░███  ██████████ ░██████████   ░░███░░███ ███░░███
     ░░░░░░░░███  ░███  ░███   ░███ ░███  ░░░░░░░░███ ░███████ ░███████   ░██████░   ░███████   ░███  ░░░  ░░░░░░░░░░  ░███░░░░░░    ░███ ░░░ ░███ ░███
    ███     ░███  ░███  ░███   ░███ ░███  ███     ░███ ░███░░░  ░███░░░  ░███░░███  ░███░░░     ░███                   ░███          ░███     ░███ ░███
    ░░█████████   ░░████████    ████████  ░░█████████  ░░██████ ░░██████ ████  █████ ░░██████  █████                  █████         █████     ░░██████ 
     ░░░░░░░░░     ░░░░░░░░     ░░░░░░░░    ░░░░░░░░░    ░░░░░░   ░░░░░ ░░░░   ░░░░░   ░░░░░░  ░░░░░                  ░░░░░         ░░░░░      ░░░░░░  
    """, style="bold cyan")
    console.print(f"[white]Version {__version__} by [bold magenta]{__author__}[/]\n")

def get_interactive_args():
    """ Run an interactive menu to get arguments from the user """
    print_banners()
    console.print("[bold]Welcome to Interactive Mode![/]\n")
    args = SimpleNamespace()

    while True:
        domain = console.input("[bold yellow]?[/] [white]Enter target domain (e.g., example.com):[/] ")
        try: args.domain = is_valid_domain(domain); break
        except argparse.ArgumentTypeError as e: console.print(f"[red]{e}[/]")

    console.print("\n--- [bold]Scan Options[/] ---")
    passive_input = console.input("[bold yellow]?[/] [white]Run passive scan? (y/n) [default: y]:[/] ")
    args.no_passive = True if passive_input.lower() == 'n' else False

    wordlist = console.input("[bold yellow]?[/] [white]Enter wordlist path for active scan (or Enter to skip):[/] ")
    args.wordlist = wordlist if wordlist else None
    args.no_active = not bool(wordlist)

    resolve_input = console.input("[bold yellow]?[/] [white]Resolve live subdomains? (y/n) [default: y]:[/] ")
    args.resolve = False if resolve_input.lower() == 'n' else True

    console.print("\n--- [bold]Additional Checks (on resolved/live domains)[/] ---")
    probe_input = console.input("[bold yellow]?[/] [white]Probe for HTTP/HTTPS servers? (y/n) [default: y]:[/] ")
    args.probe = False if probe_input.lower() == 'n' else True

    cname_input = console.input("[bold yellow]?[/] [white]Check for CNAME records? (y/n) [default: n]:[/] ")
    args.cname = True if cname_input.lower() == 'y' else False

    wayback_input = console.input("[bold yellow]?[/] [white]Query Wayback Machine? (y/n) [default: n]:[/] ")
    args.wayback = True if wayback_input.lower() == 'y' else False

    console.print("\n--- [bold]Concurrency & Output[/] ---")
    if not args.no_passive:
        concurrency = console.input(f"[bold yellow]?[/] [white]Passive scan concurrency [default: {DEFAULT_PASSIVE_CONCURRENCY}]:[/] ")
        try: args.concurrency = int(concurrency) if concurrency else DEFAULT_PASSIVE_CONCURRENCY
        except ValueError: console.print(f"[yellow]Invalid number, using {DEFAULT_PASSIVE_CONCURRENCY}.[/]"); args.concurrency = DEFAULT_PASSIVE_CONCURRENCY
    else: args.concurrency = DEFAULT_PASSIVE_CONCURRENCY

    if not args.no_active or args.resolve:
        threads = console.input(f"[bold yellow]?[/] [white]DNS threads (active/resolve) [default: {DEFAULT_RESOLVE_THREADS}]:[/] ")
        try: args.threads = int(threads) if threads else DEFAULT_RESOLVE_THREADS
        except ValueError: console.print(f"[yellow]Invalid number, using {DEFAULT_RESOLVE_THREADS}.[/]"); args.threads = DEFAULT_RESOLVE_THREADS
    else: args.threads = DEFAULT_RESOLVE_THREADS

    if args.probe:
        probe_concurrency = console.input(f"[bold yellow]?[/] [white]HTTP probe concurrency [default: {DEFAULT_PROBE_CONCURRENCY}]:[/] ")
        try: args.probe_concurrency = int(probe_concurrency) if probe_concurrency else DEFAULT_PROBE_CONCURRENCY
        except ValueError: console.print(f"[yellow]Invalid number, using {DEFAULT_PROBE_CONCURRENCY}.[/]"); args.probe_concurrency = DEFAULT_PROBE_CONCURRENCY
    else: args.probe_concurrency = DEFAULT_PROBE_CONCURRENCY

    output = console.input("[bold yellow]?[/] [white]Output file (or Enter to print to screen):[/] ")
    args.output = output if output else None
    if args.output:
        format_input = console.input("[bold yellow]?[/] [white]Output format (txt/json) [default: txt]:[/] ")
        args.output_format = format_input.lower() if format_input.lower() in ['txt', 'json'] else 'txt'
    else: args.output_format = 'txt'

    args.no_wildcard = False
    console.print("\n[green]Configuration set. Starting scan...[/]\n")
    return args

# --- Main Scan Logic (Modified by athxsec) ---

async def run_scan(args):
    """ The main scanning workflow """
    if len(sys.argv) > 1: print_banners()
    console.print(f"[bold]Target Domain:[/bold] {args.domain}\n")

    # --- Step 0: Wildcard Check ---
    if not args.no_wildcard: await check_wildcard(args.domain)

    # --- Step 1: Gather Initial Subdomains ---
    found_passive_subs = set()
    found_active_subs = set()
    initial_subdomains = set()

    # Shared connector and session for passive/wayback
    passive_resolver = aiohttp.AsyncResolver(nameservers=RESOLVERS)
    passive_connector = aiohttp.TCPConnector(resolver=passive_resolver)
    headers = {'User-Agent': USER_AGENT}

    if not args.no_passive:
        console.print(f"[*] Starting passive scans (concurrency: {args.concurrency})...", style="yellow")
        semaphore = asyncio.Semaphore(args.concurrency)
        async with aiohttp.ClientSession(headers=headers, connector=passive_connector) as session:
            passive_tasks = [
                source_crtsh(args.domain, session, semaphore, found_passive_subs),
                source_alienvault(args.domain, session, semaphore, found_passive_subs),
            ]
            await asyncio.gather(*passive_tasks)
        initial_subdomains.update(found_passive_subs)
        console.print(f"[+] Passive scans complete. Found {len(found_passive_subs)} potential subdomains.", style="green")

    if not args.no_active and args.wordlist:
        # Note: active_scan modifies results_data directly now
        await active_scan(args.domain, args.wordlist, args.threads, found_active_subs)
        initial_subdomains.update(found_active_subs)
        console.print(f"[+] Active scan complete. Added {len(found_active_subs)} potential subdomains.", style="green")

    if not initial_subdomains:
        console.print("[yellow]No potential subdomains found.[/]"); return
    console.print(f"\n[*] Total potential subdomains found: {len(initial_subdomains)}")

    # --- Step 2: Resolve & CNAME Check ---
    # Resolve ALL initial subdomains if any downstream task needs live ones
    domains_to_process_further = initial_subdomains
    if args.resolve or args.probe or args.cname or args.wayback:
        console.print(f"[*] Resolving {len(initial_subdomains)} potential subdomains (threads: {args.threads})...", style="yellow")
        # Run resolver, results go into global results_data
        await run_resolver_engine(initial_subdomains, args.threads, args.cname)
        resolved_domains = set(results_data.keys()) # Domains that had an A or CNAME record
        console.print(f"[+] Resolution complete. Found {len(resolved_domains)} live subdomains.", style="green")
        domains_to_process_further = resolved_domains
    else:
        # Populate results_data minimally if not resolving
        for sub in initial_subdomains: results_data[sub] = {}

    if not domains_to_process_further:
        console.print("[yellow]No live subdomains found after resolution.[/]"); return

    # --- Step 3: HTTP/HTTPS Probing ---
    domains_for_wayback = set()
    if args.probe:
        console.print(f"\n[*] Probing {len(domains_to_process_further)} live subdomains for web servers (concurrency: {args.probe_concurrency})...", style="yellow")
        await run_probing_engine(domains_to_process_further, args.probe_concurrency)
        probed_count = sum(1 for data in results_data.values() if data.get("http_urls"))
        console.print(f"[+] Probing complete. Found {probed_count} web servers.", style="green")
        domains_for_wayback = {sub for sub, data in results_data.items() if data.get("http_urls")}
    elif args.wayback: # If wayback is needed but probe isn't, assume all resolved domains might have web history
        domains_for_wayback = domains_to_process_further

    # --- Step 4: Wayback Machine Query ---
    if args.wayback and domains_for_wayback:
         console.print(f"\n[*] Querying Wayback Machine for {len(domains_for_wayback)} web domains (concurrency: {args.concurrency})...", style="yellow")
         semaphore = asyncio.Semaphore(args.concurrency)
         # Need a NEW session here as the previous one might be closed
         async with aiohttp.ClientSession(headers=headers, connector=passive_connector) as wayback_session:
             wayback_tasks = [source_wayback(sub, wayback_session, semaphore) for sub in domains_for_wayback]
             await asyncio.gather(*wayback_tasks)
         console.print("[+] Wayback queries complete.", style="green")

    # --- Step 5: Final Output ---
    final_live_domains = sorted(results_data.keys()) # All domains we have *any* data for (IPs, CNAMEs, etc.)
    live_count = len(final_live_domains)

    console.print(f"\n[+] [bold]Scan Complete![/]", style="green")
    if args.resolve or args.probe or args.cname or args.wayback:
        console.print(f"    [bold]└─ Found {live_count} live subdomains with details.[/]", style="bold green")
    else:
        console.print(f"    [bold]└─ Found {len(initial_subdomains)} potential subdomains (run with -r to resolve).[/]", style="bold green")


    output_list = []
    if args.resolve: # If resolve flag is set, output only domains we confirmed live
        output_list = final_live_domains
    else: # Otherwise, output all initially found domains (no extra details)
        output_list = sorted(list(initial_subdomains))

    if args.output:
        console.print(f"[*] Saving {len(output_list)} results to [bold]{args.output}[/] (format: {args.output_format})...", style="yellow")
        try:
            with open(args.output, 'w') as f:
                if args.output_format == 'json':
                    output_json_data = {domain: results_data[domain] for domain in output_list if domain in results_data}
                    json.dump(output_json_data, f, indent=4)
                else:
                    for domain in output_list: f.write(domain + '\n')
            console.print("[+] Results saved.", style="green")
        except IOError as e: console.print(f"[-] Failed to write to file: {e}", style="red")
    else:
        # Print detailed results to console if not saving to file
        console.print(f"\n--- [bold]Results[/] ({len(output_list)}) ---", style="cyan")
        if not output_list: console.print("[yellow]No results to display based on filters.[/]")
        else:
            for domain in output_list:
                # If resolving/probing, print details, otherwise just print the name
                if args.resolve or args.probe or args.cname or args.wayback:
                    print_result(domain, results_data.get(domain, {}), args)
                else:
                     console.print(f"[bold green]{domain}[/]", highlight=False)

    # Close the shared connector explicitly
    await passive_connector.close()


# --- Main Entry Point ---
def main():
    """ Main entry point """
    try:
        if len(sys.argv) > 1: args = get_cli_args()
        else: args = get_interactive_args()

        if not args.domain: console.print("[-] [red]Error: Target domain required.[/]", style="red"); sys.exit(1)
        if args.no_passive and (args.no_active or not args.wordlist):
             console.print("[-] [red]Error: Must enable passive or provide wordlist for active scan.[/]", style="red"); sys.exit(1)
        # Force resolve if any detail-oriented flags are set
        if args.probe or args.cname or args.wayback: args.resolve = True

        asyncio.run(run_scan(args))

    except KeyboardInterrupt: console.print("\n[!] Scan interrupted by user.", style="red"); sys.exit(0)
    except Exception as e:
         console.print(f"\n[!] [bold red]An unexpected error occurred:[/]", style="red")
         console.print_exception(show_locals=False); sys.exit(1)

if __name__ == "__main__":
    main()
