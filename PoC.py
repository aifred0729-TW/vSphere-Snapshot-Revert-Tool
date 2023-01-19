#!/usr/bin/python3
# PoC By Red Meow
# https://www.facebook.com/aifred0729TW/
import requests, urllib3, base64
from urllib.parse import unquote
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = "https://192.168.223.240"
vcenter_username = "administrator@vsphere.local"
vcenter_password = "!Meowmeow.local8787"

headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}

def pre_auth(base_url, headers):
    print("[*] Getting pre authentication cookie....")
    print("[*] Try URL : " + base_url + "/ui/config/h5-config?debug=false")

    try:
        r = requests.get(base_url + "/ui/config/h5-config?debug=false", headers=headers, verify=False)
    except:
        print("[!] Cannot connect the vCenter !")
        print("[!] Failed on pre_auth stage.")
        exit()

    if r.cookies['VSPHERE-UI-JSESSIONID']:
        print("[*] Successful get pre authentication cookie !!")
        print("[$] VSPHERE-UI-JSESSIONID=" + r.cookies["VSPHERE-UI-JSESSIONID"])
        pre_vsphere_ui_jsessionid = r.cookies['VSPHERE-UI-JSESSIONID']
    else:
        print("[!] VSPHERE-UI-JSESSIONID doesn't exist.")
        print("[!] Failed on pre_auth stage.")
        exit()

    return pre_vsphere_ui_jsessionid

def redirect(base_url, pre_vsphere_ui_jsessionid, headers):
    print("[*] Getting the redirect URL....")
    print("[*] Try URL : " + base_url + "/ui/login")

    cookies = {"VSPHERE-UI-JSESSIONID": pre_vsphere_ui_jsessionid}

    try:
        r = requests.get(base_url + "/ui/login", cookies=cookies, headers=headers, verify=False)
    except:
        print("[!] Cannot connect the vCenter !")
        print("[!] Failed on redirect stage.")
        exit()

    if r.history[0].headers['Location']:
        print("[*] Successful get the redirect URL !!")
        location_302 = r.history[0].headers['Location']
    else:
        print("[!] Missing the redirect URL !!")
        print("[!] Failed on redirect stage.")
        exit()

    return location_302

def login(location_302, vcenter_username, vcenter_password, pre_vsphere_ui_jsessionid, headers):

    print("[*] Try to login vCenter....")
    print("[*] Try URL : " + location_302.split("?")[0])

    cookies = {"VSPHERE-UI-JSESSIONID": pre_vsphere_ui_jsessionid}
    credential = vcenter_username + ":" + vcenter_password
    credential = base64.b64encode(credential.encode()).decode()
    credential = {"CastleAuthorization": "Basic " + credential}

    try:
        r = requests.post(location_302, data=credential, cookies=cookies, headers=headers, verify=False)
    except:
        print("[!] Cannot connect the vCenter !")
        print("[!] Failed on login stage.")
        exit()

    if r.cookies['CastleSessionvsphere.local']:
        print("[*] Successful login !!")
        print("[*] Get get new authentication cookie !!")
        print("[$] CastleSessionvsphere.local=" + r.cookies['CastleSessionvsphere.local'])
    else:
        print("[!] Login failed !!")
        print("Failed on login stage.")
        exit()

    result = r.text.strip().split()
    castle_session = r.cookies['CastleSessionvsphere.local']

    return result, castle_session

def multi_cookies(result, castle_session, pre_vsphere_ui_jsessionid, headers):

    url = result[12].split('"')[1]
    post_data = {result[16].split('"')[1]: result[17].split('"')[1], result[20].split('"')[1]: result[21].split('"')[1]}

    cookies = {}
    pre_vsphere_ui_jsessionid = {"VSPHERE-UI-JSESSIONID": pre_vsphere_ui_jsessionid}
    castle_session = {"CastleSessionvsphere.local": castle_session}
    cookies.update(pre_vsphere_ui_jsessionid)
    cookies.update(castle_session)

    print("[*] Getting other authentication cookie....")
    print("[*] Try URL : " + url)

    try:
        r = requests.post(url, data=post_data, cookies=cookies, headers=headers, verify=False)
    except:
        print("[!] Cannot connect the vCenter !!")
        print("[!] Failed on multi_cookies stage.")
        exit()

    result = r.history[0].cookies

    if len(result) == 3:
        vsphere_username = unquote(result['VSPHERE-USERNAME'])
        vsphere_client_session_index = result['VSPHERE-CLIENT-SESSION-INDEX']
        vsphere_ui_jsessionid = result['VSPHERE-UI-JSESSIONID']

        print("[*] Successful get all of the authentication cookie !!")
        print("[$] VSPHERE-USERNAME=" + vsphere_username)
        print("[$] VSPHERE-CLIENT-SESSION-INDEX=" + vsphere_client_session_index)
        print("[$] VSPHERE-UI-JSESSIONID=" + vsphere_ui_jsessionid)
    else:
        print("[!] Missing the authentication cookie.")
        print("[!] Failed on multi_cookies stage.")
        exit()

    return vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid

def xsrf_token(base_url, vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid, castle_session, headers):

    vsphere_username = {"VSPHERE-USERNAME": vsphere_username}
    vsphere_client_session_index = {"VSPHERE-CLIENT-SESSION-INDEX": vsphere_client_session_index}
    vsphere_ui_jsessionid = {"VSPHERE-UI-JSESSIONID": vsphere_ui_jsessionid}
    castle_session = {"CastleSessionvsphere.local": castle_session}

    cookies = {}
    cookies.update(vsphere_username)
    cookies.update(vsphere_client_session_index)
    cookies.update(vsphere_ui_jsessionid)
    cookies.update(castle_session)

    xml_request = {"X-Requested-With": "XMLHttpRequest"}
    headers.update(xml_request)

    print("[*] Getting xsrf token....")
    print("[*] Try URL : " + base_url + "/ui")

    try:
        r = requests.get(base_url + "/ui/", cookies=cookies, headers=headers, verify=False)
    except:
        print("[!] Cannot connect vCenter !!")
        print("[!] Failed on xsrf_token stage.")
        exit()

    if r.status_code == 200:
        print("[*] Successful pass stage 1.")
    else:
        print("[!] Status code is error.")
        print("[!] Failed on xsrf_token stage.")
        exit()

    try:
        r = requests.get(base_url + "/ui/config/h5-config?debug=false", cookies=cookies, headers=headers, verify=False)
    except:
        print("[!] Cannot connect vCenter !!")
        print("[!] Failed on xsrf_token stage.")
        exit()

    if r.status_code == 200:
        print("[*] Successful pass stage 2.")
    else:
        print("[!] Status code is error.")
        print("[!] Failed on xsrf_token stage.")
        exit()

    if r.cookies['VSPHERE-UI-XSRF-TOKEN']:
        vsphere_ui_xsrf_token = r.cookies['VSPHERE-UI-XSRF-TOKEN']
        print("[*] Successful get the xsrf token !!!")
        print("[$] VSPHERE-UI-XSRF-TOKEN=" + vsphere_ui_xsrf_token)
    else:
        print("[!] Missing the xsrf token !!")
        print("[!] Failed on xsrf_token stage.")
        exit()

    return vsphere_ui_xsrf_token

def ret_cookies(vsphere_ui_jsessionid, vsphere_username, vsphere_client_session_index, vsphere_ui_xsrf_token, castle_session):
    vsphere_ui_jsessionid = {"VSPHERE-UI-JSESSIONID": vsphere_ui_jsessionid}
    vsphere_username = {"VSPHERE-USERNAME": vsphere_username}
    vsphere_client_session_index = {"VSPHERE-CLIENT-SESSION-INDEX": vsphere_client_session_index}
    vsphere_ui_xsrf_token = {"VSPHERE-UI-XSRF-TOKEN": vsphere_ui_xsrf_token}
    castle_session = {"CastleSessionvsphere.local": castle_session}

    cookies = {}
    cookies.update(vsphere_ui_jsessionid)
    cookies.update(vsphere_username)
    cookies.update(vsphere_client_session_index)
    cookies.update(vsphere_ui_xsrf_token)
    cookies.update(castle_session)

    return cookies

def revert(machine, base_url, cookies, headers):

    # DC01 3001 DC02 3002 WS01 3004 WS02 3006
    id = ""

    if machine == "DC01":
        id = "3001"
    elif machine == "DC02":
        id = "3002"
    elif machine == "WS01":
        id = "3004"
    elif machine == "WS02":
        id = "3006"
    else:
         print("[*] No Select Machine in Database.")

    if id:
        url = f"/ui/mutation/apply/urn%3Avmomi%3AVirtualMachineSnapshot%3Asnapshot-{id}%3Afc690f35-e97e-46d5-b3ae-5da238a51518?propertyObjectType=com.vmware.vsphere.client.vm.snapshot.VmSnapshotRevertSpec"
        xsrf_header = {"X-Vsphere-Ui-Xsrf-Token": cookies["VSPHERE-UI-XSRF-TOKEN"]}
        te = {"Te": "trailers"}
        headers.update(xsrf_header)
        headers.update(te)
        json = {"suppressPowerOn": "false"}

        try:
            r = requests.post(base_url + url, json=json, cookies=cookies, headers=headers, verify=False)
        except:
            print("[!] Cannot connect vCenter !!")
            print("[!] Failed on revert stage.")
            exit()

        if r.status_code == 200:
            print("[*] Selected machine will be revert now.")
        else:
            print("[!] Status code is not 200.")

def main(base_url, vcenter_username, vcenter_password, headers):
    pre_vsphere_ui_jsessionid = pre_auth(base_url, headers)
    location_302 = redirect(base_url, pre_vsphere_ui_jsessionid, headers)
    result, castle_session = login(location_302, vcenter_username, vcenter_password, pre_vsphere_ui_jsessionid, headers)
    vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid = multi_cookies(result, castle_session, pre_vsphere_ui_jsessionid, headers)
    vsphere_ui_xsrf_token = xsrf_token(base_url, vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid, castle_session, headers)
    cookies = ret_cookies(vsphere_ui_jsessionid, vsphere_username, vsphere_client_session_index, vsphere_ui_xsrf_token, castle_session)
    while True:
        print("--------------------------------------------")
        print("[*] Available Machine : DC01 DC02 WS01 WS02")
        machine = input("[?] Select Revert Machine : ")
        revert(machine, base_url, cookies, headers)


main(base_url, vcenter_username, vcenter_password, headers)
