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

# فایل ذخیرهٔ پروکسی‌ها
proxy_file = "proxies.txt" 

# فایل تنظیمات
CONFIG_FILE = "config.json"
# تنظیمات پیش‌فرض
DEFAULT_CONFIG = {
    "max_workers": 30,
    "hard_check_sites": ["https://www.google.com", "https://www.github.com"]
}
# متغیر سراسری برای نگهداری تنظیمات بارگذاری شده
config = {} 

# منبع پروکسی‌ها (همان منبع اصلی)
proxy_source = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies&proxy_format=protocolipport&format=text"
)

# --- توابع مدیریت فایل تنظیمات ---
def load_config():
    """بارگذاری تنظیمات از فایل JSON یا ایجاد فایل پیش‌فرض."""
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            # اطمینان از وجود کلیدهای پیش‌فرض در صورت عدم وجود در فایل
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
        except json.JSONDecodeError:
            console.print(f"❌ [bold red]خطا در خواندن فایل تنظیمات [cyan]{CONFIG_FILE}[/cyan]. تنظیمات پیش‌فرض اعمال می‌شود.[/bold red]")
            config = DEFAULT_CONFIG.copy()
            save_config(config)
        except Exception as e:
            console.print(f"❌ [bold red]خطای غیرمنتظره در بارگذاری تنظیمات: {e}. تنظیمات پیش‌فرض اعمال می‌شود.[/bold red]")
            config = DEFAULT_CONFIG.copy()
            save_config(config)
    else:
        config = DEFAULT_CONFIG.copy()
        save_config(config)

def save_config(config_data):
    """ذخیره تنظیمات در فایل JSON."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=4)
        console.print(f"✅ [bold green]تنظیمات در [cyan]{CONFIG_FILE}[/cyan] ذخیره شد.[/bold green]")
    except Exception as e:
        console.print(f"❌ [bold red]خطا در ذخیره تنظیمات: {e}[/bold red]")

# --- کلاس سفارشی برای نمایش تعداد اسکان شده ---
class ScannedCountTextColumn(TextColumn):
    def __init__(self): 
        super().__init__("{task.completed}/{task.total}", style="bold magenta", justify="right")

    def render(self, task: Task) -> Text:
        """رندر کردن متن شامل تعداد پروکسی‌های اسکن شده و کل"""
        return Text(f"{task.completed}/{task.total}", style="bold magenta", justify="right")
# --- پایان کلاس سفارشی ---


def fetch_proxies(): 
    """دریافت لیست پروکسی‌ها و ذخیره در فایل با نمایشگر پیشرفت"""
    with console.status(f"[bold green]در حال دریافت پروکسی‌ها...[/bold green]", spinner="dots"):
        try:
            r = requests.get(proxy_source, timeout=15) 
            r.raise_for_status()
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            with open(proxy_file, "w") as f: 
                f.write("\n".join(lines) + "\n")
            console.print(f"✅ [bold green]تعداد پروکسی‌های دریافت‌شده: {len(lines)}[/bold green] و در [bold cyan]{proxy_file}[/bold cyan] ذخیره شد.")
        except requests.exceptions.RequestException as e:
            console.print(f"❌ [bold red]خطا در دریافت پروکسی‌ها: {e}[/bold red]")
        except Exception as e:
            console.print(f"❌ [bold red]خطای غیرمنتظره در دریافت پروکسی‌ها: {e}[/bold red]")


# --- تابع جدید برای بررسی سطح ناشناس بودن و رتبه‌بندی ---
def check_anonymity(proxy_url):
    """
    سطح ناشناس بودن یک پروکسی را تعیین و آن را رتبه‌بندی می‌کند (0-10).
    برمی‌گرداند: 0, 5, 10 یا "Unknown"
    """
    test_url = "http://azenv.net/" # یک سایت رایج برای تست ناشناس بودن پروکسی
    
    proto_part = proxy_url.split("://")[0].lower()
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy_url, "https": proxy_url }
    else:
        return "Unknown" # اگر پروتکل معتبر نباشد

    try:
        r = requests.get(test_url, proxies=proxy_dict, timeout=10) 
        r.raise_for_status()
        content = r.text

        # بررسی برای HTTP_X_FORWARDED_FOR (پروکسی شفاف)
        if "HTTP_X_FORWARDED_FOR" in content:
            return 0 # Transparent - Lowest anonymity

        # بررسی برای HTTP_VIA (پروکسی ناشناس)
        if "HTTP_VIA" in content:
            return 5 # Anonymous - Medium anonymity

        # اگر هیچ‌کدام از هدرهای بالا یافت نشد، احتمالا Elite است.
        return 10 # Elite - Highest anonymity

    except requests.exceptions.RequestException:
        return "Unknown" # خطا در اتصال به azenv.net
    except Exception:
        return "Unknown" # خطای عمومی


# --- تابع تست عادی (Soft Check) - حالا با بررسی ناشناس بودن و رتبه‌بندی ---
def test_proxy_soft(proxy):
    """
    بررسی اولیه اتصال پروکسی از طریق HTTP/HTTPS/SOCKS
    با تست روی example.com و تعیین سطح ناشناس بودن.
    """
    if "://" not in proxy or ":" not in proxy.split("://")[1]:
        return False, None, "Unknown", proxy # Added anonymity level as Unknown

    proto_part = proxy.split("://")[0].lower()
    
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy, "https": proxy }
    else:
        return False, None, "Unknown", proxy # Added anonymity level as Unknown
    
    start_time = time.time()
    try:
        test_url = "https://www.example.com" 
        r = requests.get(test_url, proxies=proxy_dict, timeout=10) 
        
        if r.status_code == 200 and "Example Domain" in r.text: 
            ping_time = round((time.time() - start_time) * 1000, 2)
            anonymity_rating = check_anonymity(proxy) # Get numerical anonymity rating
            return True, ping_time, anonymity_rating, proxy # Return anonymity rating
            
    except requests.exceptions.RequestException: 
        pass 
    except Exception: 
        pass
            
    return False, None, "Unknown", proxy # Return anonymity as Unknown for failed


# --- تابع تست سخت (Hard Check) با سایت‌های سفارشی و بررسی ناشناس بودن و رتبه‌بندی ---
def test_proxy_hard(proxy, custom_sites): # changed signature
    """
    بررسی پیشرفته‌تر اتصال پروکسی با تست روی لیست سایت‌های سفارشی
    و تعیین سطح ناشناس بودن.
    """
    if "://" not in proxy or ":" not in proxy.split("://")[1]:
        return False, None, "Unknown", proxy # Added anonymity level as Unknown

    proto_part = proxy.split("://")[0].lower()
    
    proxy_dict = {}
    if proto_part in ["http", "https", "socks4", "socks5"]:
        proxy_dict = { "http": proxy, "https": proxy }
    else:
        return False, None, "Unknown", proxy # Added anonymity level as Unknown
    
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
    return True, ping_time, anonymity_rating, proxy # Added anonymity rating

# --- تابع جدید برای تست سرعت پروکسی‌ها ---
def perform_speed_test(proxies_with_data): # Changed name to reflect more data
    """
    انجام تست سرعت دانلود برای لیست پروکسی‌های فعال.
    """
    if not proxies_with_data:
        console.print("\n⚠️ [bold yellow]هیچ پروکسی فعالی برای تست سرعت وجود ندارد.[/bold yellow]")
        return

    console.print("\n⚡ [bold blue]**در حال انجام تست سرعت برای پروکسی‌های فعال...**[/bold blue]")
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
        task = progress.add_task("[cyan]تست سرعت[/cyan]", total=len(proxies_with_data))
        
        # Use config['max_workers']
        with ThreadPoolExecutor(max_workers=config['max_workers']) as executor: 
            # We need to extract just proxy string for the speed test
            future_to_proxy_str = {executor.submit(_test_single_proxy_speed, p[0], test_file_url, file_size_bytes): p[0] for p in proxies_with_data}
            
            try:
                for future in as_completed(future_to_proxy_str):
                    proxy_str, speed_mbps = future.result()
                    if speed_mbps is not None:
                        speed_results.append((proxy_str, speed_mbps))
                        progress.console.print(f"  🚀 [bold green]{proxy_str}[/bold green] → سرعت: [bold magenta]{speed_mbps:.2f} Mbps[/bold magenta]")
                    else:
                        progress.console.print(f"  ❌ [bold red]{proxy_str}[/bold red] → تست سرعت ناموفق.")
                    progress.update(task, advance=1) 
            except KeyboardInterrupt:
                console.print("\n[bold yellow]تست سرعت متوقف شد. در حال جمع‌آوری نتایج...[/bold yellow]")
                for future in future_to_proxy_str:
                    future.cancel()

    console.print(f"✅ [bold green]تست سرعت به پایان رسید.[/bold green]")

    if speed_results:
        console.print("\n---")
        console.print(f"🔹 [bold green]نتایج تست سرعت (بر اساس بیشترین سرعت مرتب شده‌اند):[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("پروکسی", style="cyan", no_wrap=True)
        table.add_column("سرعت (Mbps)", style="green", justify="right")

        speed_results.sort(key=lambda x: x[1], reverse=True) # مرتب‌سازی بر اساس سرعت نزولی

        for proxy, speed in speed_results:
            table.add_row(proxy, f"{speed:.2f}")
        
        console.print(table)
    else:
        console.print("\n😔 [bold yellow]هیچ پروکسی با تست سرعت موفق پیدا نشد.[/bold yellow]")
    console.print("---\n")

def _test_single_proxy_speed(proxy, url, file_size_bytes):
    """
    تابع کمکی برای تست سرعت یک پروکسی.
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
    تابع مشترک برای بررسی پروکسی‌ها با متد تست دلخواه (Soft یا Hard)
    """
    if not os.path.exists(proxy_file): 
        console.print(f"⚠️ [bold yellow]لیست پروکسی در {proxy_file} ذخیره نشده است. ابتدا به روز رسانی کنید.[/bold yellow]")
        time.sleep(2)
        return

    with open(proxy_file, "r") as f: 
        proxies = [line.strip() for line in f.readlines() if "://" in line]

    if not proxies:
        console.print(f"⚠️ [bold yellow]فایل پروکسی {proxy_file} خالی است. لطفاً ابتدا به روز رسانی کنید.[/bold yellow]")
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
        task = progress.add_task("[cyan]تست پروکسی‌ها[/cyan]", total=len(proxies))
        
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
                        
                        progress.console.print(f"  ✔️ [bold {console_color}]{proxy_str}[/bold {console_color}] → {success_message} ⏱️ پینگ: [bold magenta]{ping} ms[/bold magenta] 🕵️ سطح ناشناس بودن: [bold blue]{anonymity_rating}[/bold blue]/10")
                    else:
                        failed_proxies_count += 1
                    progress.update(task, advance=1) 
            except KeyboardInterrupt:
                console.print("\n[bold yellow]تست پروکسی‌ها متوقف شد. در حال جمع‌آوری نتایج...[/bold yellow]")
                for future in future_to_proxy:
                    future.cancel()
            
    console.print(f"✅ [bold green]تست پروکسی‌ها به پایان رسید.[/bold green]")
    console.print(f"    [bold green]تعداد پروکسی‌های فعال:[/bold green] [green]{len(working_proxies)}[/green]")
    console.print(f"    [bold red]تعداد پروکسی‌های ناموفق:[/bold red] [red]{failed_proxies_count}[/red]")


    if working_proxies:
        console.print("\n---")
        console.print(f"🔹 [bold green]پروکسی‌های فعال (بر اساس کمترین پینگ مرتب شده‌اند):[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("پروکسی", style="cyan", no_wrap=True)
        table.add_column("پینگ (ms)", style="green", justify="right")
        table.add_column("ناشناس بودن (0-10)", style="blue", justify="center") # New column header

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
        console.print("\n😔 [bold yellow]هیچ پروکسی فعالی پیدا نشد.[/bold yellow]")
    console.print("---\n")

    if working_proxies:
        while True:
            speed_test_choice = console.input("[bold yellow]آیا مایلید تست سرعت برای پروکسی‌های فعال انجام شود؟ (y/n):[/bold yellow] ").strip().lower()
            if speed_test_choice == "y":
                # For speed test, we only need proxy string.
                # working_proxies contains (proxy_str, ping, anonymity_rating)
                proxies_for_speed_test = [(p[0], p[1]) for p in working_proxies] # Only pass proxy string and ping
                perform_speed_test(proxies_for_speed_test)
                break
            elif speed_test_choice == "n":
                console.print("[bold green]تست سرعت انجام نخواهد شد.[/bold green]")
                break
            else:
                console.print("⚠️ [bold red]ورودی نامعتبر! لطفاً 'y' یا 'n' وارد کنید.[/bold red]")
                time.sleep(1)

# --- توابع تنظیمات ---
def configure_max_workers():
    """تنظیم حداکثر تعداد Workerها برای تست همزمان."""
    global config
    while True:
        try:
            current_max_workers = config['max_workers']
            new_max_workers = console.input(f"[bold yellow]تعداد حداکثر Worker فعلی: {current_max_workers}. مقدار جدید را وارد کنید (یک عدد صحیح مثبت):[/bold yellow] ").strip()
            if not new_max_workers: # Allow empty input to keep current value
                console.print(f"[bold green]تعداد Workerها بدون تغییر باقی ماند: {current_max_workers}[/bold green]")
                break
            
            new_max_workers = int(new_max_workers)
            if new_max_workers <= 0:
                console.print("❌ [bold red]تعداد Worker باید یک عدد صحیح مثبت باشد.[/bold red]")
            else:
                config['max_workers'] = new_max_workers
                save_config(config)
                console.print(f"✅ [bold green]تعداد حداکثر Workerها به {new_max_workers} تنظیم شد.[/bold green]")
                break
        except ValueError:
            console.print("❌ [bold red]ورودی نامعتبر! لطفاً یک عدد صحیح وارد کنید.[/bold red]")
        except Exception as e:
            console.print(f"❌ [bold red]خطایی رخ داد: {e}[/bold red]")
        time.sleep(1)

def configure_hard_check_sites():
    """تنظیم سایت‌های سفارشی برای Hard Check."""
    global config
    console.print("\n[bold yellow]--- تنظیم سایت‌های Hard Check ---[/bold yellow]")
    console.print(f"سایت‌های فعلی: [cyan]{', '.join(config['hard_check_sites'])}[/cyan]")
    console.print("شما می‌توانید 1 یا 2 سایت را برای Hard Check تعیین کنید.")
    console.print("مثال: https://www.example.com")
    
    new_sites = []
    
    for i in range(1, 3):
        while True:
            site_url = console.input(f"[bold yellow]URL سایت {i} (یا خالی برای پایان):[/bold yellow] ").strip()
            if not site_url:
                if i == 1: # Must enter at least one site
                    console.print("⚠️ [bold red]حداقل یک سایت برای Hard Check مورد نیاز است.[/bold red]")
                    continue
                else:
                    break # User finished entering sites
            
            if not (site_url.startswith("http://") or site_url.startswith("https://")):
                console.print("❌ [bold red]URL نامعتبر! باید با http:// یا https:// شروع شود.[/bold red]")
            else:
                new_sites.append(site_url)
                break
    
    if new_sites:
        config['hard_check_sites'] = new_sites
        save_config(config)
        console.print(f"✅ [bold green]سایت‌های Hard Check به: [cyan]{', '.join(new_sites)}[/cyan] تنظیم شد.[/bold green]")
    else:
        console.print("[bold yellow]تنظیمات سایت‌های Hard Check بدون تغییر باقی ماند.[/bold yellow]")
    time.sleep(1)

def settings_menu():
    """منوی تنظیمات."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear') 
        console.print("\n[bold blue]--- منوی تنظیمات ---[/bold blue]")
        settings_table = Table(box=None, show_header=False, show_edge=True, border_style="white")
        settings_table.add_column("Option", justify="left", style="white")
        settings_table.add_row("1_تنظیم Max Workers")
        settings_table.add_row("2_تنظیم سایت‌های Hard Check")
        settings_table.add_row("3_بازگشت به منوی اصلی")
        console.print(settings_table, justify="center")

        cmd_input = console.input("\n[bold yellow]شماره گزینه مورد نظر را وارد کنید:[/bold yellow] ").strip()

        if cmd_input == "1":
            configure_max_workers()
            console.input("[bold green]✅ تنظیمات تکمیل شد. دکمه Enter را برای ادامه فشار دهید...[/bold green]")
        elif cmd_input == "2":
            configure_hard_check_sites()
            console.input("[bold green]✅ تنظیمات تکمیل شد. دکمه Enter را برای ادامه فشار دهید...[/bold green]")
        elif cmd_input == "3":
            break
        else:
            console.print("⚠️ [bold red]ورودی نامعتبر![/bold red] لطفاً یک عدد از 1 تا 3 وارد کنید.")
            time.sleep(2)


if __name__ == "__main__":
    console.print("[bold blue]--- ابزار بررسی پروکسی ---[/bold blue]")
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
        menu_table.add_row(Text("version 3", style="dim white", justify="center")) # Changed version to 3
        
        console.print(menu_table, justify="center")
        
        cmd_input = console.input("\n[bold yellow]شماره گزینه مورد نظر را وارد کنید:[/bold yellow] ").strip()
        
        if cmd_input == "1":
            fetch_proxies()
            console.input("[bold green]✅ به روز رسانی کامل شد. دکمه Enter را برای ادامه فشار دهید...[/bold green]")
        elif cmd_input == "2": 
            check_proxies_with_method(
                test_proxy_soft, 
                "در حال بررسی پروکسی‌ها (Soft Check)...", 
                "اتصال موفق!"
            )
            console.input("[bold green]✅ بررسی پروکسی‌ها کامل شد. دکمه Enter را برای ادامه فشار دهید...[/bold green]")
        elif cmd_input == "3": 
            check_proxies_with_method(
                test_proxy_hard, 
                "در حال بررسی پروکسی‌ها (Hard Check)...", 
                "اتصال واقعی موفق!",
                custom_sites=config['hard_check_sites'] # Pass custom sites
            )
            console.input("[bold green]✅ بررسی پروکسی‌ها کامل شد. دکمه Enter را برای ادامه فشار دهید...[/bold green]")
        elif cmd_input == "4": 
            settings_menu()
        elif cmd_input == "5": 
            console.print("[bold red]خداحافظ![/bold red]")
            break
        else:
            console.print("⚠️ [bold red]ورودی نامعتبر![/bold red] لطفاً یک عدد از 1 تا 5 وارد کنید.")
            time.sleep(2)
