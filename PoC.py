#!/usr/bin/python3
# PoC By Red Meow
# https://www.facebook.com/aifred0729TW/
import requests, urllib3, base64, json
from urllib.parse import unquote
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = ""
vcenter_username = ""
vcenter_password = ""

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

def revert(machine, snapshot_data, base_url, cookies, headers):

    snapshot = []
    machine_id = []
    count = 0
    find = False
    for i in snapshot_data:
        machine_id.append([])
        machine_id[count].append(i)
        machine_id[count].append(len(snapshot_data[i]))
        count += 1
    for i in range(len(machine_id)):
        for j in range(machine_id[i][1]):
            if machine == snapshot_data[machine_id[i][0]][j][1]:
                serverGuid = snapshot_data[machine_id[i][0]][j][3]
                find = True

    if find:
        url = f"/ui/mutation/apply/urn:vmomi:VirtualMachineSnapshot:{machine}:{serverGuid}?propertyObjectType=com.vmware.vsphere.client.vm.snapshot.VmSnapshotRevertSpec"
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
            exit()
    else:
         print("[*] No Select Machine in Database.")


def get_api_session(base_url, vcenter_username, vcenter_password):

    print("[*] Getting the API session....")
    print("[*] Username : " + vcenter_username)
    print("[*] Password : " + vcenter_password)

    credential = vcenter_username + ":" + vcenter_password
    credential = base64.b64encode(credential.encode()).decode()

    auth_header = {"authorization": "Basic " + credential}

    try:
        r = requests.post(base_url + "/api/session", headers=auth_header, verify=False)
    except:
        print("[!] Cannot connect vCenter !!")
        print("[!] Failed on get_api_session stage.")
        exit()

    if r.status_code == 201:
        print("[*] Successful create API session.")
        print("[$] API session : " + r.text.strip('"'))
        result = r.text.strip('"')
    else:
        print("[!] Failed to create API session.")
        print("[!] Failed on get_api_session stage.")
        exit()

    return result

def get_machine_list(base_url, api_session):

    print("[*] Getting the machine list....")

    try:
        r = requests.get(base_url + "/api/vcenter/vm", headers=api_session, verify=False)
    except:
        print("[!] Cannot connect vCenter !!")
        print("[!] Failed on get_machine_list stage.")
        exit()

    if r.status_code == 200:
        print("[*] Successfal get machine list.")
        result = json.loads(r.text)
    else:
        print("[!] Failed to get machine list.")
        print("[!] Failed on get_machine_list stage.")
        exit()

    return result

def get_snapshot_id(base_url, machine_list, cookies):

    print("[*] Getting snapshot id....")

    machines = {}
    snapshot_data = {}

    for i in range(len(machine_list)):
        tmp_machine_name = machine_list[i]['name']
        tmp_machine_id = machine_list[i]['vm']
        tmp_machine = {tmp_machine_name: tmp_machine_id}
        machines.update(tmp_machine)

    for i in machines:
        try:
            r = requests.get(base_url + f"/ui/data/properties/urn:vmomi:VirtualMachine:{machines[i]}:fc690f35-e97e-46d5-b3ae-5da238a51518?properties=name,snapshot,diskUsage", cookies=cookies, headers=headers, verify=False)
        except:
            print("[!] Cannot connect vCenter !!")
            print("[!] Failed on get_snapshot_id stage.")
            exit()

        result = json.loads(r.text)
        tmp_snapshots = {}
        tmp_snapshots = snapshot_sort(tmp_snapshots, result, result, 0, 0, 0)
        snapshot_data.update(tmp_snapshots)

    return snapshot_data

def snapshot_sort(snapshot_dict, original_data, result, root_count, child_count, count):
    
    data = []

    if result['snapshot'] == None:
        return snapshot_dict

    elif "childSnapshotList" in result:

        machine_name = original_data['name']
        try:
            for i in snapshot_dict[machine_name]:
                data.append(i)
            data.append([])
            data[count].append(result['childSnapshotList'][child_count]['name'])
            data[count].append(result['childSnapshotList'][child_count]['snapshot']['value'])
            data[count].append(result['childSnapshotList'][child_count]['vm']['value'])
            data[count].append(result['childSnapshotList'][child_count]['snapshot']['serverGuid'])
            tmp_snapshots = {machine_name : data}
            snapshot_dict.update(tmp_snapshots)
            child_count += 1
            count += 1
            snapshot_sort(snapshot_dict, original_data, result, root_count, child_count, count)
            return snapshot_dict
        except:
            return snapshot_dict

    elif "rootSnapshotList" in result['snapshot']:
        machine_name = result['name']
        data.append([])
        data[count].append(original_data['snapshot']['rootSnapshotList'][root_count]['name'])
        data[count].append(original_data['snapshot']['rootSnapshotList'][root_count]['snapshot']['value'])
        data[count].append(original_data['snapshot']['rootSnapshotList'][root_count]['vm']['value'])
        data[count].append(original_data['snapshot']['rootSnapshotList'][root_count]['snapshot']['serverGuid'])
        tmp_snapshots = {machine_name : data}
        snapshot_dict.update(tmp_snapshots)
        count += 1

        if "childSnapshotList" in original_data['snapshot']['rootSnapshotList'][root_count] and original_data['snapshot']['rootSnapshotList'][root_count]['childSnapshotList'] != None:
            snapshot_sort(snapshot_dict, original_data, result['snapshot']['rootSnapshotList'][root_count], root_count, child_count, count)
            root_count += 1
            return snapshot_dict
        else:
            return snapshot_dict
    else:
        return snapshot_dict

def show_snapshots(snapshot_data):
    
    print("[*] Available Machine : ", end="")
    machine_id = []
    count = 0
    for i in snapshot_data:
        print(i, end=" ")
        machine_id.append([])
        machine_id[count].append(i)
        machine_id[count].append(len(snapshot_data[i]))
        count += 1
    print()
    print("   Machine Name\tSnapshot Name\tSnapshot ID\tVM ID  \tserverGuid")
    print("   {:<12}\t{:<13}\t{:<13}\t{:<7}\t{:<36}".format("-"*12, "-"*13, "-"*13, "-"*7, "-"*36))
    for i in range(len(machine_id)):
        for j in range(machine_id[i][1]):
            if j == 0:
                print("   {:<12}\t{:<13}\t{:<13}\t{:<7}\t{:<36}".format(machine_id[i][0], snapshot_data[machine_id[i][0]][j][0], snapshot_data[machine_id[i][0]][j][1], snapshot_data[machine_id[i][0]][j][2], snapshot_data[machine_id[i][0]][j][3]))
            else:
                print(" "*5 + "{:<3}\t{:<13}\t{:<13}\t{:<7}\t{:<36}".format("└─────────", snapshot_data[machine_id[i][0]][j][0], snapshot_data[machine_id[i][0]][j][1], snapshot_data[machine_id[i][0]][j][2], snapshot_data[machine_id[i][0]][j][3]))
    
def main():
    api_session = {"vmware-api-session-id": get_api_session(base_url, vcenter_username, vcenter_password)}
    machine_list = get_machine_list(base_url, api_session)
    pre_vsphere_ui_jsessionid = pre_auth(base_url, headers)
    location_302 = redirect(base_url, pre_vsphere_ui_jsessionid, headers)
    result, castle_session = login(location_302, vcenter_username, vcenter_password, pre_vsphere_ui_jsessionid, headers)
    vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid = multi_cookies(result, castle_session, pre_vsphere_ui_jsessionid, headers)
    vsphere_ui_xsrf_token = xsrf_token(base_url, vsphere_username, vsphere_client_session_index, vsphere_ui_jsessionid, castle_session, headers)
    cookies = ret_cookies(vsphere_ui_jsessionid, vsphere_username, vsphere_client_session_index, vsphere_ui_xsrf_token, castle_session)
    snapshot_data = get_snapshot_id(base_url, machine_list, cookies)
    while True:
        print("--------------------------------------------")
        show_snapshots(snapshot_data)
        print("[*] Please enter the snapshot ID to revert machine.")
        machine = input("[?] Snapshot ID : ")
        revert(machine, snapshot_data, base_url, cookies, headers)

main()
