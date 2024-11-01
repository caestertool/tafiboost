import os, sys, time, uuid, random, re
from os import system as sm
from sys import platform as pf
from time import sleep as sp
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests, rich
    from rich import print as rp
    from rich.panel import Panel as pan
except ModuleNotFoundError:
    sm('python -m pip install requests rich')

# Colors
R = "[bold red]"
G = "[bold green]"
Y = "[bold yellow]"
C = "[bold cyan]"
W = "[bold white]"

# Clear terminal and show logo
def clear():
    if pf in ['win32', 'win64']:
        sm('cls')
    else:
        sm('clear')
    logo()

def ensure_directories():
    paths = [
        '/sdcard/BOOSTINGTOOL',
        '/sdcard/BOOSTINGTOOL/1.txt',
        '/sdcard/BOOSTINGTOOL/2.txt',
        '/sdcard/BOOSTINGTOOL/3.txt',
        '/sdcard/BOOSTINGTOOL/4.txt',
        '/sdcard/BOOSTINGTOOL/5.txt',
        '/sdcard/BOOSTINGTOOL/6.txt',
        '/sdcard/BOOSTINGTOOL/7.txt',
        '/sdcard/BOOSTINGTOOL/8.txt',
        '/sdcard/BOOSTINGTOOL/9.txt',
        '/sdcard/BOOSTINGTOOL/10.txt'
    ]
    for path in paths:
        if os.path.isdir(path):
            continue  
        elif os.path.isfile(path):
            continue  
        elif path.endswith(".txt"):
            with open(path, 'a'):  
                pass
        else:
            os.makedirs(path)  

# Display the logo
def logo():
    rp(pan("""%s              Token Getter Script""" % Y, title="%sTOKEN FETCHER" % Y, subtitle="%sDEVELOP BY EDWARD" % R, border_style="bold cyan"))

# Main function to get input paths
def main():
    clear()
    input_path = input(f"Enter file path for UID|Password combinations:~")
    credentials = load_credentials(input_path)
    
    # Call function to create an empty file for saving tokens at the chosen output path
    output_path = create_empty_output_file()

    if credentials:
        success, fail = process_tokens(credentials)
        display_results(success, fail)
        save_tokens(success, output_path)  # Pass output path for saving tokens
        end_option()
    else:
        rp(f"{R}No valid credentials provided, but output file created: {output_path}")
        end_option()

# Load credentials from file
def load_credentials(input_path):
    try:
        with open(input_path, "r") as file:
            credentials = [line.strip() for line in file if '|' in line]
        if not credentials:
            rp(f"{R}No valid UID|Password lines found in file.")
            return []
        return credentials
    except FileNotFoundError:
        rp(f"{R}File not found. Please check the file path and try again.")
        return []

# Create an empty output file for saving tokens
def create_empty_output_file():
    rp(f"{C}Choose where to save successful tokens:")
    rp(f"{G}A: /sdcard/BOOSTINGTOOL/1.txt")
    rp(f"{Y}B: /sdcard/BOOSTINGTOOL/2.txt")
    rp(f"{Y}C: /sdcard/BOOSTINGTOOL/3.txt")
    rp(f"{Y}D: /sdcard/BOOSTINGTOOL/4.txt")
    rp(f"{Y}E: /sdcard/BOOSTINGTOOL/5.txt")
    rp(f"{Y}F: /sdcard/BOOSTINGTOOL/6.txt")
    rp(f"{Y}G: /sdcard/BOOSTINGTOOL/7.txt")
    rp(f"{Y}H: /sdcard/BOOSTINGTOOL/8.txt")
    rp(f"{Y}I: /sdcard/BOOSTINGTOOL/9.txt")
    rp(f"{Y}J: /sdcard/BOOSTINGTOOL/10.txt")

    save_choice = input(f"{C}Enter choice (A to J):~ {Y}").strip().upper()
    
    output_path = {
        "A": "/sdcard/BOOSTINGTOOL/1.txt",
        "B": "/sdcard/BOOSTINGTOOL/2.txt",
        "C": "/sdcard/BOOSTINGTOOL/3.txt",
        "D": "/sdcard/BOOSTINGTOOL/4.txt",
        "E": "/sdcard/BOOSTINGTOOL/5.txt",
        "F": "/sdcard/BOOSTINGTOOL/6.txt",
        "G": "/sdcard/BOOSTINGTOOL/7.txt",
        "H": "/sdcard/BOOSTINGTOOL/8.txt",
        "I": "/sdcard/BOOSTINGTOOL/9.txt",
        "J": "/sdcard/BOOSTINGTOOL/10.txt",
    }.get(save_choice)

    if output_path:
        # Create the directory if it does not exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)  # Automatically creates the full path
        rp(f"{C}Directory created or already exists: {os.path.dirname(output_path)}")
        
        # Create an empty file or clear if already exists
        open(output_path, 'w').close()  # Create or empty the file
        rp(f"{C}Output file created at {output_path}")
        
        return output_path
    else:
        rp(f"{R}Invalid choice. Cannot create output file.")
        sys.exit()  # Exit the program if invalid choice

# Process tokens from input list with ThreadPoolExecutor
def process_tokens(credentials):
    success = []
    fail_count = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(get_token, line.split('|', 1)[0], line.split('|', 1)[1]): line for line in credentials}

        for future in as_completed(futures):
            uid = futures[future].split('|', 1)[0]  # Get the UID only
            token = future.result()

            if token:
                rp(f"{G}SUCCESS EXTRACT - {uid}")
                account_type = check_account_type(token)  # Check account type
                if account_type:
                    rp(f"{Y}Account belongs to a bot: {uid}")
                else:
                    success.append(token)  # Store only the token
            else:
                rp(f"{R}FAILED EXTRACT - {uid}")
                fail_count += 1

    return success, fail_count

# Check if account is a bot
def check_account_type(access_token):
    try:
        response = requests.get(f"https://graph.facebook.com/me?access_token={access_token}&fields=id,name,is_verified")
        if response.status_code == 200:
            user_info = response.json()
            return user_info.get('is_verified', False)  # True if it is verified, can be adjusted as necessary
    except Exception as e:
        rp(f"{R}Failed to check account type: {str(e)}")
    return False

# Display summary of results
def display_results(success, fail_count):
    rp(f"{C}TOTAL EXTRACTED SUCCESS: {G}{len(success)}")
    rp(f"{C}TOTAL FAILED: {R}{fail_count}")

# Save tokens to the specified output path
def save_tokens(success, output_path):
    with open(output_path, "a") as out_file:  # Open in append mode to save tokens
        out_file.write("\n".join(success) + "\n")
    rp(f"{G}Tokens successfully saved to {output_path}")

# End option for user to continue or exit
def end_option():
    rp(f"{C}Process completed. Choose an option:")
    rp(f"{G}1: Return to Main Menu")
    rp(f"{R}2: Exit")

    choice = input(f"{C}Enter choice (1 or 2):~ {Y}").strip()
    if choice == "1":
        main()
    else:
        rp(f"{Y}Exiting... Goodbye!")
        sys.exit()

# Get token using UID and password
def get_token(uid, password):
    access_token = '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    data = {
        'adid': str(uuid.uuid4()),
        'format': 'json',
        'device_id': str(uuid.uuid4()),
        'cpl': 'true',
        'family_device_id': str(uuid.uuid4()),
        'credentials_type': 'device_based_login_password',
        'error_detail_type': 'button_with_disabled',
        'source': 'device_based_login',
        'email': uid,
        'password': password,
        'access_token': access_token,
        'generate_session_cookies': '1',
        'meta_inf_fbmeta': '',
        'advertiser_id': str(uuid.uuid4()),
        'currently_logged_in_userid': '0',
        'locale': 'en_US',
        'client_country_code': 'US',
        'method': 'auth.login',
        'fb_api_req_friendly_name': 'authenticate',
        'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        'api_key': '62f8ce9f74b12f84c123cc23437a4a32',
    }
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 8.0.0; SM-A720F Build/R16NW) [FBAN/Orca-Android;FBAV/196.0.0.29.99;FBPN/com.facebook.orca;FBLC/en_US;FBBV/135374479;FBCR/SMART;FBMF/samsung;FBBD/samsung;FBDV/SM-A720F;FBSV/8.0.0;FBCA/armeabi-v7a:armeabi;FBDM/{density=3.0,width=1080,height=1920};FB_FW/1;]",
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'graph.facebook.com',
        'X-FB-Net-HNI': str(random.randint(10000, 99999)),
        'X-FB-SIM-HNI': str(random.randint(10000, 99999)),
        'X-FB-Connection-Type': 'MOBILE.LTE',
        'X-FB-Connection-Bandwidth': str(random.randint(20000000, 30000000)),
        'X-FB-Friendly-Name': 'ViewerReactionsMutation',
        'X-FB-HTTP-Engine': 'Liger',
    }

    response = requests.post("https://b-graph.facebook.com/auth/login", headers=headers, data=data, allow_redirects=False).json()
    return response.get('access_token')

if __name__ == "__main__":
    ensure_directories()  # Ensure directories are created at the start
    main()
