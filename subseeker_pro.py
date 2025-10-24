#!/usr/bin/env python3
#
# Tool:     SubSeeker-Pro
# Author:   athxsec
# Version:  1.6.0 (Resolver Edition)
#
# A high-speed, asyncio-based subdomain enumeration tool
# with interactive and command-line modes.
#
# NEW in 1.6.0:
# - Added -r / --resolve flag to validate all found subs and show only LIVE ones.
# - Refactored resolve worker for use by both active scan and resolver.
# - Removed unreliable/dead sources: BufferOver and Riddler.
#

import argparse
import asyncio
import aiohttp
import aiodns
import re
import sys
import random
from types import SimpleNamespace
from bs4 import BeautifulSoup
from rich.console import Console

# --- Metadata ---
__author__ = "athxsec"
__version__ = "1.6.0"

# Initialize rich console
console = Console()

# Global sets for results
all_found_subdomains = set()
live_subdomains = set()

# --- Configuration ---
RESOLVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
SESSION_TIMEOUT = aiohttp.ClientTimeout(total=25)


async def check_wildcard(domain: str) -> bool:
    """
    Checks for a wildcard DNS record on the target domain.
    """
    console.print(f"[*] Checking for wildcard DNS on [bold cyan]{domain}[/]...", style="yellow")
    try:
        resolver = aiodns.DNSResolver()
        resolver.nameservers = RESOLVERS
        random_sub = f"u-are-a-wildcard-{random.randint(1000, 9999)}.{domain}"
        await resolver.query(random_sub, 'A')
        console.print("[!] [bold red]Wildcard DNS detected![/] Results may contain false positives.", style="red")
        return True
    except aiodns.error.DNSError:
        console.print("[+] No wildcard DNS detected.", style="green")
        return False
    except Exception as e:
        console.print(f"[-] Error checking for wildcard: {e}", style="dim")
        return False


async def save_result(subdomain: str, output_set: set, print_found: bool = True):
    """
    Thread-safe way to save a found subdomain.
    """
    # Clean the subdomain before saving
    subdomain = subdomain.strip().lower()
    if subdomain not in output_set:
        output_set.add(subdomain)
        if print_found:
            console.print(f"[+] Found: [bold green]{subdomain}[/]", highlight=False)


# --- Passive Sources (Created by athxsec) ---

async def source_crtsh(domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
    """
    Get subdomains from crt.sh
    """
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
                                subdomains = name_value.split('\n')
                                for sub in subdomains:
                                    if sub.endswith(domain) and '*' not in sub:
                                        # Save to the main 'all_found' list
                                        await save_result(sub, all_found_subdomains)
                    except aiohttp.ContentTypeError:
                        console.print(f"[-] crt.sh error: Received non-JSON response (maybe HTML error).", style="red")
                else:
                    console.print(f"[-] crt.sh error: Status {response.status}", style="red")
        except asyncio.TimeoutError:
            console.print(f"[-] crt.sh error: Connection timed out after {SESSION_TIMEOUT.total}s", style="red")
        except Exception as e:
            console.print(f"[-] crt.sh error: {e}", style="dim")

async def source_alienvault(domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
    """
    Get subdomains from AlienVault OTX
    """
    async with semaphore:
        console.print("[*] Querying AlienVault OTX...", style="dim")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            async with session.get(url, timeout=SESSION_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '').strip()
                        if hostname.endswith(domain) and '*' not in hostname:
                            await save_result(hostname, all_found_subdomains)
                else:
                    console.print(f"[-] AlienVault error: Status {response.status}", style="red")
        except asyncio.TimeoutError:
            console.print(f"[-] AlienVault error: Connection timed out after {SESSION_TIMEOUT.total}s", style="red")
        except Exception as e:
            console.print(f"[-] AlienVault error: {e}", style="dim")


# --- DNS Resolution Engine (Created by athxsec) ---

async def resolve_worker(domain_queue: asyncio.Queue, resolver: aiodns.DNSResolver, output_set: set, print_found: bool):
    """
    Worker task for resolving domain names from a queue.
    """
    while True:
        try:
            domain_to_check = await domain_queue.get()
            try:
                # Perform an 'A' record query
                await resolver.query(domain_to_check, 'A')
                # If it succeeds, save it to the specified output set
                await save_result(domain_to_check, output_set, print_found)
            except aiodns.error.DNSError:
                # NXDOMAIN, NoAnswer, etc. - means it's not live
                pass
            
            domain_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception:
            pass # Ignore other worker errors


async def run_resolver_engine(domains_to_check: set, num_threads: int, output_set: set, print_found: bool = True):
    """
    High-speed DNS resolver for validating subdomains.
    """
    domain_queue = asyncio.Queue()
    for domain in domains_to_check:
        domain_queue.put_nowait(domain)

    resolver = aiodns.DNSResolver()
    resolver.nameservers = RESOLVERS

    # Create worker tasks
    workers = [
        asyncio.create_task(resolve_worker(domain_queue, resolver, output_set, print_found))
        for _ in range(num_threads)
    ]

    # Wait for the queue to be processed
    await domain_queue.join()

    # Cancel the worker tasks
    for worker in workers:
        worker.cancel()
    await asyncio.gather(*workers, return_exceptions=True)


async def active_scan(domain: str, wordlist_file: str, num_threads: int):
    """
    Actively brute-force subdomains using a wordlist and threading.
    """
    console.print(f"[*] Starting active scan with {num_threads} workers...", style="yellow")
    
    # We create a temporary set of domains to check from the wordlist
    domains_to_check = set()
    try:
        with open(wordlist_file, 'r') as f:
            for line in f:
                word = line.strip()
                if word:
                    domains_to_check.add(f"{word}.{domain}")
    except FileNotFoundError:
        console.print(f"[-] Wordlist not found: {wordlist_file}", style="red")
        return
        
    if not domains_to_check:
        console.print("[-] Wordlist is empty.", style="red")
        return

    console.print(f"[*] Loaded {len(domains_to_check)} subdomains into the queue.", style="yellow")
    
    # Run the resolver engine
    # We print results as we find them and save them to the main 'all_found' list
    await run_resolver_engine(domains_to_check, num_threads, all_found_subdomains, print_found=True)


def get_cli_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description=f"SubSeeker-Pro {__version__} by {__author__} - A powerful asyncio-based subdomain finder.")
    parser.add_argument("-d", "--domain", help="The target domain (e.g., google.com)")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file for active scan")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent workers for active/resolve scan (default: 100)")
    parser.add_argument("-o", "--output", help="Path to the output file to save results (shows all results, or only resolved if -r is used)")
    parser.add_argument("-r", "--resolve", action="store_true", help="Resolve all found subdomains and show only live ones")
    parser.add_argument("--no-passive", action="store_true", help="Skip all passive scans")
    parser.add_argument("--no-active", action="store_true", help="Skip the active (brute-force) scan")
    parser.add_argument("--no-wildcard", action="store_true", help="Skip the wildcard detection")
    parser.add_argument("-c", "--concurrency", type=int, default=2, help="Number of concurrent passive scans (default: 2)")
    return parser.parse_args()


def print_banners():
    """
    Prints the main ASCII art banners.
    """
    console.print(r"""
    ███████╗ ██╗   ██╗██████╗ ███████╗███████╗███████╗██╗  ██╗███████╗██████╗         ██████╗ ██████╗  ██████╗ 
    ██╔════╝ ██║   ██║██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗        ██╔══██╗██╔══██╗██╔═══██╗
    ███████╗ ██║   ██║██████╔╝███████╗█████╗  █████╗  █████╔╝ █████╗  ██████╔╝ █████╗ ██████╔╝██████╔╝██║   ██║
    ╚════██║ ██║   ██║██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══██╗ ╚════╝ ██╔═══╝ ██╔══██╗██║   ██║
    ███████║ ╚██████╔╝██████╔╝███████║███████╗███████╗██║  ██╗███████╗██║  ██║        ██║     ██║  ██║╚██████╔╝
    ╚══════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝        ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
                                                                                                            
    """, style="bold cyan")
    
    console.print(f"[white]Version {__version__} by [bold magenta]{__author__}[/]\n")


def get_interactive_args():
    """
    Run an interactive menu to get arguments from the user.
    """
    print_banners()
    console.print("[bold]Welcome to Interactive Mode![/]\n")
    
    args = SimpleNamespace()
    
    while True:
        domain = console.input("[bold yellow]?[/] [white]Enter target domain (e.g., google.com):[/] ")
        if domain:
            args.domain = domain
            break
        console.print("[red]Domain cannot be empty.[/]")

    wordlist = console.input("[bold yellow]?[/] [white]Enter path to wordlist (or press Enter to skip active scan):[/] ")
    args.wordlist = wordlist if wordlist else None
    args.no_active = not bool(wordlist)

    # NEW: Ask to resolve
    resolve_input = console.input("[bold yellow]?[/] [white]Resolve live subdomains? (y/n) [default: y]:[/] ")
    args.resolve = False if resolve_input.lower() == 'n' else True

    if not args.no_active or args.resolve:
        threads = console.input("[bold yellow]?[/] [white]Enter resolve/scan threads [default: 100]:[/] ")
        try:
            args.threads = int(threads) if threads else 100
        except ValueError:
            console.print("[yellow]Invalid number, using 100 threads.[/]")
            args.threads = 100
    else:
        args.threads = 100
    
    concurrency = console.input("[bold yellow]?[/] [white]Enter passive scan concurrency [default: 2]:[/] ")
    try:
        args.concurrency = int(concurrency) if concurrency else 2
    except ValueError:
        console.print("[yellow]Invalid number, using 2.[/]")
        args.concurrency = 2

    output = console.input("[bold yellow]?[/] [white]Enter output file (or press Enter to skip saving):[/] ")
    args.output = output if output else None

    args.no_passive = False
    args.no_wildcard = False
    
    console.print("\n[green]Configuration set. Starting scan...[/]\n")
    return args


async def run_scan(args):
    """
    The main scanning logic.
    """
    if len(sys.argv) > 1:
        print_banners()
    
    console.print(f"[bold]Target Domain:[/bold] {args.domain}\n")

    if not args.no_wildcard:
        await check_wildcard(args.domain)

    if not args.no_passive:
        console.print(f"[*] Starting passive scans (concurrency: {args.concurrency})...", style="yellow")
        
        semaphore = asyncio.Semaphore(args.concurrency)
        
        resolver = aiohttp.AsyncResolver(nameservers=RESOLVERS)
        connector = aiohttp.TCPConnector(resolver=resolver)
        
        headers = {'User-Agent': USER_AGENT}
        
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            passive_tasks = [
                source_crtsh(args.domain, session, semaphore),
                source_alienvault(args.domain, session, semaphore),
            ]
            await asyncio.gather(*passive_tasks)
        console.print("[+] Passive scans complete.", style="green")

    if not args.no_active and args.wordlist:
        await active_scan(args.domain, args.wordlist, args.threads)
        console.print("[+] Active scan complete.", style="green")

    # --- NEW: Resolve Step ---
    if args.resolve:
        console.print(f"\n[*] Resolving all {len(all_found_subdomains)} found subdomains...")
        # Run the resolver engine on all found subs, saving results to the 'live_subdomains' set
        # We set 'print_found' to False to avoid re-printing "Found: ..."
        await run_resolver_engine(all_found_subdomains, args.threads, live_subdomains, print_found=False)
        console.print(f"[+] Resolution complete. Found {len(live_subdomains)} live subdomains.", style="green")

    # --- Results ---
    console.print(f"\n[+] [bold]Scan Complete![/] Found {len(all_found_subdomains)} total subdomains.", style="green")

    # Decide which list to show/save
    if args.resolve:
        console.print(f"    [bold]└─ Found {len(live_subdomains)} LIVE subdomains.[/]", style="bold green")
        results_to_show = sorted(list(live_subdomains))
        final_list_name = "Live Subdomains"
    else:
        results_to_show = sorted(list(all_found_subdomains))
        final_list_name = "All Found Subdomains"
    
    if args.output:
        console.print(f"[*] Saving {len(results_to_show)} {final_list_name} to [bold]{args.output}[/]...", style="yellow")
        try:
            with open(args.output, 'w') as f:
                for sub in results_to_show:
                    f.write(sub + '\n')
            console.print("[+] Results saved.", style="green")
        except IOError as e:
            console.print(f"[-] Failed to write to file: {e}", style="red")
    else:
        console.print(f"\n--- [bold]{final_list_name}[/] ({len(results_to_show)}) ---", style="cyan")
        for sub in results_to_show:
            console.print(sub, style="green")


def main():
    """
    Main entry point. Decides to run in interactive or CLI mode.
    """
    try:
        if len(sys.argv) > 1:
            args = get_cli_args()
        else:
            args = get_interactive_args()
            
        if not args.domain:
            console.print("[-] [red]Error: A target domain must be provided.[/] Use -d <domain> or run in interactive mode.", style="red")
            sys.exit(1)
            
        if args.no_passive and (args.no_active or not args.wordlist):
            console.print("[-] [red]Error: You must enable passive scan or provide a wordlist for active scan.[/]", style="red")
            sys.exit(1)

        asyncio.run(run_scan(args))

    except KeyboardInterrupt:
        console.print("\n[!] Scan interrupted by user.", style="red")
        sys.exit(0)

if __name__ == "__main__":
    main()