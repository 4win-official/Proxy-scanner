import requests
import os
import time
import json 
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn, Task
from rich.text import Text 

# Console object for rich output
console = Console()

# Proxy list file
proxy_file = "proxies.txt" 

# Configuration file
CONFIG_FILE = "config.json"
# Default configurations
DEFAULT_CONFIG = {
    "max_workers": 30,
    "hard_check_sites": ["https://www.google.com", "https://www.github.com"]
}
# Global variable to hold loaded configurations
config = {} 

# Proxy source (the main source)
proxy_source = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies&proxy_format=protocolipport&format=text"
)

# --- Configuration File Management Functions ---
def load_config():
    """Loads configurations from JSON file or creates a default file."""
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            # Ensure default keys exist if missing in the file
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
        except json.JSONDecodeError:
            console.print(f"❌ [bold red]Error reading configuration file [cyan]{CONFIG_FILE}[/cyan]. Default settings applied.[/bold red]")
            config = DEFAULT_CONFIG.copy()
            save_config(config)
        except Exception as e:
            console.print(f"❌ [bold red]Unexpected error loading configurations: {e}. Default settings applied.[/bold red]")
            config = DEFAULT_CONFIG.copy()
            save_config(config)
    else:
        config = DEFAULT_CONFIG.copy()
        save_config(config)

def save_config(config_data):
    """Saves configurations to JSON file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=4)
        console.print(f"✅ [bold green]Configurations saved to [cyan]{CONFIG_FILE}[/cyan].[/bold green]")
    except Exception as e:
        console.print(f"❌ [bold red]Error saving configurations: {e}[/bold red]")

# --- Custom Class for Displaying Scanned Count ---
class ScannedCountTextColumn(TextColumn):
    def __init__(self): 
        super().__init__("{task.completed}/{task.total}", style="bold magenta", justify="right")

    def render(self, task: Task) -> Text:
        """Renders the text showing the number of scanned and total proxies"""
        return Text(f"{task.completed}/{task.total}", style="bold magenta", justify="right")
# --- End of Custom Class ---


def fetch_proxies(): 
    """Fetches the proxy list and saves it to a file with progress indicator."""
    with console.status(f"[bold green]Fetching proxies...[/bold green]", spinner="dots"):
        try:
            r = requests.get(proxy_source, timeout=15) 
            r.raise_for_status()
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            with open(proxy_file, "w") as f: 
                f.write("\n".join(lines) + "\n")
            console.print(f"✅ [bold green]Proxies received: {len(lines)}[/bold green] and saved to [bold cyan]{proxy_file}[/bold cyan].")
        except requests.exceptions.RequestException as e:
            console.print(f"❌ [bold red]Error fetching proxies: {e}[/bold red]")
        except Exception as e:
            console.print(f"❌ [bold red]Unexpected error fetching proxies: {e}[/bold red]")


# --- Function for checking anonymity level and rating ---
def check_anonymity(proxy_url):
    """
    Determines the anonymity level of a proxy and rates it (0-10).
    Returns: 0, 5, 10 or "Unknown"
    """
    test_url = "http://azenv.net/" # A common site for proxy anonymity testing
    
    proto_part = proxy_url.split("://")[0].lower()
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy_url, "https": proxy_url }
    else:
        return "Unknown" # Invalid protocol

    try:
        r = requests.get(test_url, proxies=proxy_dict, timeout=10) 
        r.raise_for_status()
        content = r.text

        # Check for HTTP_X_FORWARDED_FOR (Transparent Proxy)
        if "HTTP_X_FORWARDED_FOR" in content:
            return 0 # Transparent - Lowest anonymity

        # Check for HTTP_VIA (Anonymous Proxy)
        if "HTTP_VIA" in content:
            return 5 # Anonymous - Medium anonymity

        # If neither header is found, it is likely Elite.
        return 10 # Elite - Highest anonymity

    except requests.exceptions.RequestException:
        return "Unknown" # Error connecting to azenv.net
    except Exception:
        return "Unknown" # General error


# --- Soft Check Function (with anonymity rating) ---
def test_proxy_soft(proxy):
    """
    Initial proxy connection check via HTTP/HTTPS/SOCKS
    by testing on example.com and determining the anonymity level.
    """
    if "://" not in proxy or ":" not in proxy.split("://")[1]:
        return False, None, "Unknown", proxy 

    proto_part = proxy.split("://")[0].lower()
    
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy, "https": proxy }
    else:
        return False, None, "Unknown", proxy 
    
    start_time = time.time()
    try:
        test_url = "https://www.example.com" 
        r = requests.get(test_url, proxies=proxy_dict, timeout=10) 
        
        if r.status_code == 200 and "Example Domain" in r.text: 
            ping_time = round((time.time() - start_time) * 1000, 2)
            anonymity_rating = check_anonymity(proxy) # Get numerical anonymity rating
            return True, ping_time, anonymity_rating, proxy 
            
    except requests.exceptions.RequestException: 
        pass 
    except Exception: 
        pass
            
    return False, None, "Unknown", proxy # Return anonymity as Unknown for failed


# --- Hard Check Function (with custom sites and anonymity rating) ---
def test_proxy_hard(proxy, custom_sites): 
    """
    More advanced proxy connection check by testing on a list of custom sites
    and determining the anonymity level.
    """
    if "://" not in proxy or ":" not in proxy.split("://")[1]:
        return False, None, "Unknown", proxy 

    proto_part = proxy.split("://")[0].lower()
    
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy, "https": proxy }
    else:
        return False, None, "Unknown", proxy 
    
    start_time = time.time()
    
    # Iterate through custom sites
    for site_url in custom_sites:
        try:
            r = requests.get(site_url, proxies=proxy_dict, timeout=15) 
            if not (r.status_code == 200 and r.text): 
                return False, None, "Unknown", proxy # If any site fails, the proxy fails
        except requests.exceptions.RequestException: 
            return False, None, "Unknown", proxy 
        except Exception: 
            return False, None, "Unknown", proxy 
            
    # If all custom sites passed, check anonymity
    anonymity_rating = check_anonymity(proxy) # Get numerical anonymity rating
    
    ping_time = round((time.time() - start_time) * 1000, 2)
    return True, ping_time, anonymity_rating, proxy 

# --- Function for proxy speed test ---
def perform_speed_test(proxies_with_data): 
    """
    Performs a download speed test for the list of active proxies.
    """
    if not proxies_with_data:
        console.print("\n⚠️ [bold yellow]No active proxies available for speed test.[/bold yellow]")
        return

    console.print("\n⚡ [bold blue]**Performing speed test for active proxies...**[/bold blue]")
    speed_results = []
    test_file_url = "https://speed.cloudflare.com/__down?bytes=1000000" # 1 MB file from Cloudflare
    file_size_bytes = 1000000 # 1 MB

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(), 
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
        ScannedCountTextColumn(), 
        "•",
        TimeRemainingColumn(), 
        transient=False
    ) as progress:
        task = progress.add_task("[cyan]Speed Test[/cyan]", total=len(proxies_with_data))
        
        # Use config['max_workers']
        with ThreadPoolExecutor(max_workers=config['max_workers']) as executor: 
            # We need to extract just proxy string for the speed test
            future_to_proxy_str = {executor.submit(_test_single_proxy_speed, p[0], test_file_url, file_size_bytes): p[0] for p in proxies_with_data}
            
            try:
                for future in as_completed(future_to_proxy_str):
                    proxy_str, speed_mbps = future.result()
                    if speed_mbps is not None:
                        speed_results.append((proxy_str, speed_mbps))
                        progress.console.print(f"  🚀 [bold green]{proxy_str}[/bold green] → Speed: [bold magenta]{speed_mbps:.2f} Mbps[/bold magenta]")
                    else:
                        progress.console.print(f"  ❌ [bold red]{proxy_str}[/bold red] → Speed test failed.")
                    progress.update(task, advance=1) 
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Speed test interrupted. Gathering results...[/bold yellow]")
                for future in future_to_proxy_str:
                    future.cancel()

    console.print(f"✅ [bold green]Speed test finished.[/bold green]")

    if speed_results:
        console.print("\n---")
        console.print(f"🔹 [bold green]Speed Test Results (Sorted by highest speed):[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Proxy", style="cyan", no_wrap=True)
        table.add_column("Speed (Mbps)", style="green", justify="right")

        speed_results.sort(key=lambda x: x[1], reverse=True) # Sort by speed descending

        for proxy, speed in speed_results:
            table.add_row(proxy, f"{speed:.2f}")
        
        console.print(table)
    else:
        console.print("\n😔 [bold yellow]No proxy with a successful speed test was found.[/bold yellow]")
    console.print("---\n")

    if working_proxies: # Note: This line uses 'working_proxies' from the outer scope if called from check_proxies_with_method
        while True:
            speed_test_choice = console.input("[bold yellow]Do you want to run a speed test on active proxies? (y/n):[/bold yellow] ").strip().lower()
            if speed_test_choice == "y":
                # working_proxies contains (proxy_str, ping, anonymity_rating)
                proxies_for_speed_test = [(p[0], p[1]) for p in working_proxies] # Only pass proxy string and ping
                perform_speed_test(proxies_for_speed_test)
                break
            elif speed_test_choice == "n":
                console.print("[bold green]Speed test will not be performed.[/bold green]")
                break
            else:
                console.print("⚠️ [bold red]Invalid input! Please enter 'y' or 'n'.[/bold red]")
                time.sleep(1)

def _test_single_proxy_speed(proxy, url, file_size_bytes):
    """
    Helper function to test the speed of a single proxy.
    """
    if "://" not in proxy or ":" not in proxy.split("://")[1]:
        return proxy, None

    proto_part = proxy.split("://")[0].lower()
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy, "https": proxy }
    else:
        return proxy, None

    try:
        start_time = time.time()
        with requests.get(url, proxies=proxy_dict, timeout=60, stream=True) as r: 
            r.raise_for_status()
            bytes_downloaded = 0
            for chunk in r.iter_content(chunk_size=8192):
                bytes_downloaded += len(chunk)
                
        end_time = time.time()
        duration = end_time - start_time

        if duration > 0 and bytes_downloaded >= file_size_bytes: 
            speed_bps = (file_size_bytes * 8) / duration # bits per second
            speed_mbps = speed_bps / (1024 * 1024) # Mbps
            return proxy, speed_mbps
        else:
            return proxy, None 

    except requests.exceptions.RequestException: 
        return proxy, None
    except Exception: 
        return proxy, None


def check_proxies_with_method(test_function, title_message, success_message, custom_sites=None): 
    """
    Generic function for checking proxies with a chosen test method (Soft or Hard).
    """
    if not os.path.exists(proxy_file): 
        console.print(f"⚠️ [bold yellow]Proxy list not saved in {proxy_file}. Please update first.[/bold yellow]")
        time.sleep(2)
        return

    with open(proxy_file, "r") as f: 
        proxies = [line.strip() for line in f.readlines() if "://" in line]

    if not proxies:
        console.print(f"⚠️ [bold yellow]Proxy file {proxy_file} is empty. Please update first.[/bold yellow]")
        time.sleep(2)
        return

    console.print(f"\n🔍 [bold blue]**{title_message}**[/bold blue]")
    working_proxies = []
    failed_proxies_count = 0 

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(), 
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
        ScannedCountTextColumn(), 
        "•",
        TimeRemainingColumn(), 
        transient=False
    ) as progress:
        task = progress.add_task("[cyan]Testing Proxies[/cyan]", total=len(proxies))
        
        # Use config['max_workers']
        with ThreadPoolExecutor(max_workers=config['max_workers']) as executor: 
            future_to_proxy = {}
            for proxy in proxies:
                if test_function == test_proxy_hard:
                    future_to_proxy[executor.submit(test_function, proxy, custom_sites)] = proxy
                else: # For test_proxy_soft
                    future_to_proxy[executor.submit(test_function, proxy)] = proxy
            
            try:
                for future in as_completed(future_to_proxy):
                    # Both test_proxy_soft and test_proxy_hard now return 4 values: success, ping, anonymity_rating, proxy_str
                    success, ping, anonymity_rating, proxy_str = future.result() 
                    if success:
                        working_proxies.append((proxy_str, ping, anonymity_rating)) # Store 3 values
                        console_color = "green"
                        if anonymity_rating == 0:
                            console_color = "red" # Transparent is red
                        elif anonymity_rating == 5:
                            console_color = "yellow" # Anonymous is yellow
                        
                        progress.console.print(f"  ✔️ [bold {console_color}]{proxy_str}[/bold {console_color}] → {success_message} ⏱️ Ping: [bold magenta]{ping} ms[/bold magenta] 🕵️ Anonymity: [bold blue]{anonymity_rating}[/bold blue]/10")
                    else:
                        failed_proxies_count += 1
                    progress.update(task, advance=1) 
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Proxy test interrupted. Gathering results...[/bold yellow]")
                for future in future_to_proxy:
                    future.cancel()
            
    console.print(f"✅ [bold green]Proxy testing finished.[/bold green]")
    console.print(f"    [bold green]Active Proxies Found:[/bold green] [green]{len(working_proxies)}[/green]")
    console.print(f"    [bold red]Failed Proxies:[/bold red] [red]{failed_proxies_count}[/red]")


    if working_proxies:
        console.print("\n---")
        console.print(f"🔹 [bold green]Active Proxies (Sorted by lowest ping):[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Proxy", style="cyan", no_wrap=True)
        table.add_column("Ping (ms)", style="green", justify="right")
        table.add_column("Anonymity (0-10)", style="blue", justify="center") # New column header

        working_proxies.sort(key=lambda x: x[1]) # Sort by ping

        for proxy_data in working_proxies:
            proxy, ping, anonymity_rating = proxy_data
            anonymity_display_color = "green"
            if anonymity_rating == 0:
                anonymity_display_color = "red"
            elif anonymity_rating == 5:
                anonymity_display_color = "yellow"
            
            table.add_row(proxy, str(ping), Text(str(anonymity_rating), style=f"bold {anonymity_display_color}"))
        
        console.print(table)
    else:
        console.print("\n😔 [bold yellow]No active proxies were found.[/bold yellow]")
    console.print("---\n")

    if working_proxies:
        while True:
            speed_test_choice = console.input("[bold yellow]Do you want to run a speed test on active proxies? (y/n):[/bold yellow] ").strip().lower()
            if speed_test_choice == "y":
                # working_proxies contains (proxy_str, ping, anonymity_rating)
                proxies_for_speed_test = [(p[0], p[1]) for p in working_proxies] # Only pass proxy string and ping
                perform_speed_test(proxies_for_speed_test)
                break
            elif speed_test_choice == "n":
                console.print("[bold green]Speed test will not be performed.[/bold green]")
                break
            else:
                console.print("⚠️ [bold red]Invalid input! Please enter 'y' or 'n'.[/bold red]")
                time.sleep(1)

# --- Configuration Functions ---
def configure_max_workers():
    """Sets the maximum number of Workers for concurrent testing."""
    global config
    while True:
        try:
            current_max_workers = config['max_workers']
            new_max_workers = console.input(f"[bold yellow]Current Max Workers: {current_max_workers}. Enter new value (a positive integer):[/bold yellow] ").strip()
            if not new_max_workers: # Allow empty input to keep current value
                console.print(f"[bold green]Max Workers remains unchanged: {current_max_workers}[/bold green]")
                break
            
            new_max_workers = int(new_max_workers)
            if new_max_workers <= 0:
                console.print("❌ [bold red]Max Workers must be a positive integer.[/bold red]")
            else:
                config['max_workers'] = new_max_workers
                save_config(config)
                console.print(f"✅ [bold green]Max Workers set to {new_max_workers}.[/bold green]")
                break
        except ValueError:
            console.print("❌ [bold red]Invalid input! Please enter an integer.[/bold red]")
        except Exception as e:
            console.print(f"❌ [bold red]An error occurred: {e}[/bold red]")
        time.sleep(1)

def configure_hard_check_sites():
    """Sets custom sites for Hard Check."""
    global config
    console.print("\n[bold yellow]--- Hard Check Sites Configuration ---[/bold yellow]")
    console.print(f"Current sites: [cyan]{', '.join(config['hard_check_sites'])}[/cyan]")
    console.print("You can specify 1 or 2 sites for Hard Check.")
    console.print("Example: https://www.example.com")
    
    new_sites = []
    
    for i in range(1, 3):
        while True:
            site_url = console.input(f"[bold yellow]Site URL {i} (or empty to finish):[/bold yellow] ").strip()
            if not site_url:
                if i == 1: # Must enter at least one site
                    console.print("⚠️ [bold red]At least one site is required for Hard Check.[/bold red]")
                    continue
                else:
                    break # User finished entering sites
            
            if not (site_url.startswith("http://") or site_url.startswith("https://")):
                console.print("❌ [bold red]Invalid URL! Must start with http:// or https://.[/bold red]")
            else:
                new_sites.append(site_url)
                break
    
    if new_sites:
        config['hard_check_sites'] = new_sites
        save_config(config)
        console.print(f"✅ [bold green]Hard Check sites set to: [cyan]{', '.join(new_sites)}[/cyan].[/bold green]")
    else:
        console.print("[bold yellow]Hard Check sites configuration remains unchanged.[/bold yellow]")
    time.sleep(1)

def settings_menu():
    """Settings menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear') 
        console.print("\n[bold blue]--- Settings Menu ---[/bold blue]")
        settings_table = Table(box=None, show_header=False, show_edge=True, border_style="white")
        settings_table.add_column("Option", justify="left", style="white")
        settings_table.add_row("1_Configure Max Workers")
        settings_table.add_row("2_Configure Hard Check Sites")
        settings_table.add_row("3_Return to Main Menu")
        console.print(settings_table, justify="center")

        cmd_input = console.input("\n[bold yellow]Enter the option number:[/bold yellow] ").strip()

        if cmd_input == "1":
            configure_max_workers()
            console.input("[bold green]✅ Settings complete. Press Enter to continue...[/bold green]")
        elif cmd_input == "2":
            configure_hard_check_sites()
            console.input("[bold green]✅ Settings complete. Press Enter to continue...[/bold green]")
        elif cmd_input == "3":
            break
        else:
            console.print("⚠️ [bold red]Invalid input![/bold red] Please enter a number from 1 to 3.")
            time.sleep(2)


if __name__ == "__main__":
    console.print("[bold blue]--- Proxy Checker Tool ---[/bold blue]")
    os.system('cls' if os.name == 'nt' else 'clear') 
    
    load_config() # Load configuration at startup
    
    while True:
        menu_table = Table(box=None, show_header=False, show_edge=True, border_style="white")
        menu_table.add_column("Option", justify="left", style="white")
        
        menu_table.add_row("1_update")
        menu_table.add_row("2_check (Soft)") 
        menu_table.add_row("3_check (Hard)") 
        menu_table.add_row("4_settings") 
        menu_table.add_row("5_exit")     
        # Changed style to "dim white" for smaller text
        menu_table.add_row(Text(f"Max Workers: {config['max_workers']}", style="dim white", justify="center"))
        menu_table.add_row(Text(f"Hard Check Sites: {', '.join(config['hard_check_sites'])}", style="dim white", justify="center"))
        menu_table.add_row(Text("version 3", style="dim white", justify="center")) 
        
        console.print(menu_table, justify="center")
        
        cmd_input = console.input("\n[bold yellow]Enter the option number:[/bold yellow] ").strip()
        
        if cmd_input == "1":
            fetch_proxies()
            console.input("[bold green]✅ Update complete. Press Enter to continue...[/bold green]")
        elif cmd_input == "2": 
            check_proxies_with_method(
                test_proxy_soft, 
                "Testing Proxies (Soft Check)...", 
                "Connection Successful!"
            )
            console.input("[bold green]✅ Proxy checking complete. Press Enter to continue...[/bold green]")
        elif cmd_input == "3": 
            check_proxies_with_method(
                test_proxy_hard, 
                "Testing Proxies (Hard Check)...", 
                "Real Connection Successful!",
                custom_sites=config['hard_check_sites'] # Pass custom sites
            )
            console.input("[bold green]✅ Proxy checking complete. Press Enter to continue...[/bold green]")
        elif cmd_input == "4": 
            settings_menu()
        elif cmd_input == "5": 
            console.print("[bold red]Goodbye![/bold red]")
            break
        else:
            console.print("⚠️ [bold red]Invalid input![/bold red] Please enter a number from 1 to 5.")
            time.sleep(2)
