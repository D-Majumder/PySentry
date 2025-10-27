import psutil
import time
import logging
import os
import winreg
import ctypes
import sys

# --- Set up logging to print nicely ---
log = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# ---
# CONFIGURATION BLOCK 1: NETWORK SCANNER (Tuning Required!)
# ---
# TODO: These paths are specific to YOUR computer. 
# For this to work on other machines, a user MUST update these paths.
# Or, you could make these paths more generic (e.g., by using environment variables).
KNOWN_GOOD_PATHS = {
    # Browsers
    "chrome.exe": "C:\\Program Files\\Google\\Chrome\\Application",
    "firefox.exe": "C:\\Program Files\\Mozilla Firefox",
    "msedge.exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application",
    
    # Windows System
    "svchost.exe": "C:\\Windows\\System32",
    "explorer.exe": "C:\\Windows",
    "SearchHost.exe": "C:\\Windows\\SystemApps",
    "backgroundTaskHost.exe": "C:\\Windows\\System32",
    "SystemSettings.exe": "C:\\Windows\\ImmersiveControlPanel",
    "System": "", # 'System' is a special kernel process with no path
    "pwsh.exe": "C:\\Program Files\\PowerShell",

    # Microsoft Office / OneDrive 
    # NOTE: '91629' is your user folder. This MUST be changed for other users.
    "OneDrive.exe": "C:\\Users\\91629\\AppData\\Local\\Microsoft\\OneDrive", 
    "Teams.exe": "C:\\Users\\91629\\AppData\\Local\\Microsoft\\Teams", 
    "ms-teams.exe": "C:\\Program Files\\WindowsApps",
    "OfficeClickToRun.exe": "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun",
    
    # Your Bitdefender Antivirus
    "bdservicehost.exe": "C:\\Program Files\\Bitdefender",
    "bdvpnService.exe": "C:\\Program Files\\Bitdefender",
    "bdagent.exe": "C:\\Program Files\\Bitdefender",
    "wsccommunicator.exe": "C:\\Program Files\\Bitdefender",
    "ProductAgentService.exe": "C:\\Program Files\\Bitdefender",
    
    # Other common apps (MUST BE TUNED)
    "Code.exe": "C:\\Users\\91629\\AppData\\Local\\Programs\\Microsoft VS Code", 
    "py.exe": "C:\\Windows",
    "WhatsApp.exe": "C:\\Program Files\\WindowsApps",
    "RiotClientServices.exe": "C:\\Riot Games\\Riot Client",
}

# ---
# CONFIGURATION BLOCK 2: PERSISTENCE SCANNER (Tuned)
# ---
KNOWN_SAFE_STARTUPS = [
    "onedrive.exe",
    "teams.exe",
    "bitdefender",
    "whatsapp.exe",
    "code.exe",
    "microsoft",
    "windows defender",
    "discord",
    "free download manager",
    "epicgameslauncher",
    "lghub",
    "proton vpn",
    "riotclient",
    "docker desktop",
]

# ---
# TOOL 1: NETWORK SCANNER FUNCTION (WITH ACTIVE RESPONSE)
# ---
def run_network_scan():
    """
    Scans active network connections, validates them, and gives the
    option to terminate suspicious processes.
    """
    
    log.info("--- Starting Advanced Network Scan (with Path Verification) ---")
    
    trusted_paths_lower = {k.lower(): v.lower() for k, v in KNOWN_GOOD_PATHS.items()}
    suspicious_processes = {}

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        log.error("Access Denied. This tool must be run as Administrator.")
        return

    for conn in connections:
        if not (conn.status == 'ESTABLISHED' and conn.pid is not None):
            continue
            
        try:
            # Get the full process details
            proc = psutil.Process(conn.pid)
            proc_name = proc.name()
            proc_path = proc.exe()
            proc_name_lower = proc_name.lower()
            
            is_suspicious = False 
            
            if proc_name_lower not in trusted_paths_lower:
                # --- DETECTION 1: Unknown Process ---
                log.warning(f"!!! SUSPICIOUS ACTIVITY DETECTED !!!")
                log.warning(f"  Process:     {proc_name} (PID: {conn.pid})")
                log.warning(f"  Path:        {proc_path}") 
                log.warning(f"  Reason:      Process is UNKNOWN (not on the 'Known Good' list).")
                is_suspicious = True
            
            else: # Process name is known, let's check path and port
                # --- DETECTION 2: Impersonation ---
                expected_path_start = trusted_paths_lower[proc_name_lower]
                if expected_path_start and not proc_path.lower().startswith(expected_path_start):
                    log.critical(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    log.critical(f"!!! HIGH-SEVERITY ALERT: PROCESS IMPERSONATION !!!")
                    log.critical(f"  Trusted Name:   {proc_name}")
                    log.critical(f"  Suspicious Path: {proc_path}")
                    log.critical(f"  Expected Path:   {expected_path_start}...")
                    log.critical(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    is_suspicious = True

                # --- DETECTION 3: Suspicious Port ---
                KNOWN_GOOD_PORTS = [80, 443, 53, 5222, 5228] # HTTP, HTTPS, DNS, WhatsApp, Google Svcs
                
                if conn.raddr and conn.raddr.ip == '127.0.0.1':
                    continue # Ignore safe localhost traffic
                
                if conn.raddr and conn.raddr.port not in KNOWN_GOOD_PORTS:
                    log.warning(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    log.warning(f"!!! HEURISTIC WARNING: SUSPICIOUS PORT USAGE !!!")
                    log.warning(f"  Process:     {proc_name} (PID: {proc.pid})")
                    log.warning(f"  Reason:      Connecting to non-standard remote port: {conn.raddr.port}")
                    log.warning(f"  Destination: {conn.raddr.ip}")
                    log.warning(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    is_suspicious = True

            if is_suspicious:
                suspicious_processes[proc.pid] = proc_name

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    log.info("--- Network Scan Finished ---")

    # ---
    # ACTIVE RESPONSE BLOCK
    # ---
    if not suspicious_processes:
        log.info("Scan complete. No active threats found.")
    else:
        log.critical("\n" + "!"*40)
        log.critical("  ACTIVE THREATS DETECTED")
        log.critical("!"*40)
        unique_threats = {pid: name for pid, name in suspicious_processes.items()}
        for pid, name in unique_threats.items():
            log.warning(f"  - Threat: {name} (PID: {pid})")
        
        print("\n")
        try:
            choice = input("Do you want to terminate all suspicious processes? (y/n): ").strip().lower()
        except KeyboardInterrupt:
            log.info("\nScan aborted. No action taken.")
            return

        if choice == 'y':
            log.info("--- INITIATING ACTIVE RESPONSE ---")
            for pid, name in unique_threats.items():
                try:
                    proc = psutil.Process(pid)
                    proc.kill()
                    log.info(f"[BLOCKED] Successfully terminated {name} (PID: {pid})")
                except psutil.NoSuchProcess:
                    log.warning(f"[INFO] Process {name} (PID: {pid}) already closed.")
                except psutil.AccessDenied:
                    log.error(f"[FAILED] Access denied. Could not terminate {name} (PID: {pid}).")
            log.info("--- ACTIVE RESPONSE COMPLETE ---")
        else:
            log.info("No action taken. Threats are still running.")


# ---
# TOOL 2: PERSISTENCE SCANNER FUNCTION
# ---
def run_persistence_scan():
    """
    Scans the most common registry "Run" keys for persistence.
    """
    log.info("--- Starting Persistence Scan (Registry) ---")
    log.info("Scanning HKEY_CURRENT_USER Run key...\n")
    
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    found_suspicious_activity = False
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        
        i = 0
        while True:
            try:
                name, data, type = winreg.EnumValue(key, i)
                i += 1
                is_safe = False
                
                for safe_item in KNOWN_SAFE_STARTUPS:
                    if safe_item.lower() in data.lower():
                        is_safe = True
                        break
                
                if is_safe:
                    log.info(f"[SAFE]   Name: {name}")
                    log.info(f"         Path: {data}\n")
                else:
                    log.warning(f"[SUSPICIOUS] Name: {name}")
                    log.warning(f"             Path: {data}")
                    log.warning(f"             Reason: Not on the 'Known Safe' list.\n")
                    found_suspicious_activity = True
                    
            except OSError:
                break
                
        winreg.CloseKey(key)
        
    except FileNotFoundError:
        log.error(f"Could not find registry key: {key_path}")
    except Exception as e:
        log.error(f"An error occurred: {e}")

    if not found_suspicious_activity:
        log.info("No suspicious startup items found.")
    log.info("--- Persistence Scan Finished ---")


# ---
# HELPER FUNCTION: ADMIN CHECK
# ---
def is_admin():
    """Checks if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ---
# MAIN MENU FUNCTION
# ---
def main():
    """Main menu for the Cyber Suite."""
    
    if not is_admin():
        log.error("This suite requires Administrator privileges to scan all processes and registry keys.")
        log.error("Please right-click the script or terminal and 'Run as Administrator'.")
        input("\nPress Enter to exit...")
        sys.exit()

    while True:
        print("\n" + "="*40)
        print("    PY-SENTRY: SYSTEM AUDIT SUITE 🛡️")
        print("="*40)
        print("1. Run Active Network Scan (Detect & Block)")
        print("2. Run Persistence Scan (Detect Only)")
        print("3. Run ALL Scans (Full System Audit)")
        print("4. Exit")
        print("-"*40)
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            run_network_scan()
        elif choice == '2':
            run_persistence_scan()
        elif choice == '3':
            log.info("--- STARTING FULL SYSTEM AUDIT ---")
            run_network_scan()
            print("\n" + "-"*40 + "\n")
            run_persistence_scan()
            log.info("--- FULL SYSTEM AUDIT COMPLETE ---")
        elif choice == '4':
            log.info("Exiting. Stay safe!")
            break
        else:
            log.warning("Invalid choice. Please enter a number between 1 and 4.")
            
        if choice != '4':
            input("\nScan complete. Press Enter to return to the menu...")

# ---
# SCRIPT ENTRY POINT
# ---
if __name__ == "__main__":
    main()
