#!/usr/bin/env python3
"""
Purpose:
    Login to UCS servers
    Get the Device ID and Security Token
    Logout
"""
import xml.etree.ElementTree as ET
import yaml
import requests
from urllib3.exceptions import InsecureRequestWarning


def ucs_login(base_url, user, password):
    """
    Login to UCS Server.
    Get outCookie for subsequent requests.
    * Update function with connection failure code.
    """
    url_path = "nuova"
    url = base_url + url_path
    payload = f"<aaaLogin inName='{user}' inPassword='{password}'></aaaLogin>"
    headers = {"Content-Type": "application/xml"}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False
    )
    xml_root = ET.fromstring(response.content)
    out_cookie = xml_root.attrib["outCookie"]
    return out_cookie


def ucs_logout(base_url, out_cookie):
    """
    Gracefully Logout from Server
    """
    url_path = "nuova"
    url = base_url + url_path
    payload = f"<aaaLogout inCookie='{out_cookie}'></aaaLogout>"
    headers = {"Content-Type": "application/xml"}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False
    )
    xml_root = ET.fromstring(response.content)
    out_status = xml_root.attrib["outStatus"]
    return out_status


def get_connection_state(base_url, out_cookie):
    """
    Get Device Claim Status
    """
    url_path = "connector/Systems"
    url = base_url + url_path
    payload = {}
    headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    system_info = response.json()[0]
    connection_info = {}
    connection_info["ConnectionState"] = system_info["ConnectionState"]
    connection_info["AccountOwnershipState"] = system_info["AccountOwnershipState"]
    connection_info["AccountOwnershipName"] = system_info["AccountOwnershipName"]
    return connection_info


def get_device_identifier(base_url, out_cookie):
    """
    Get Device Identifier
    """
    url_path = "connector/DeviceIdentifiers"
    url = base_url + url_path
    payload = {}
    headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    device_id = response.json()[0]["Id"]
    return device_id


def get_security_tokens(base_url, out_cookie):
    """
    Get Security Token Value
    """
    url_path = "connector/SecurityTokens"
    url = base_url + url_path
    payload = {}
    headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    if isinstance(response.json(), list):
        token = response.json()[0]["Token"]
        return token
    if isinstance(response.json(), dict):
        if response.json()["code"] == "InvalidRequest":
            message = response.json()["message"]
            return message


def workflow():
    """
    Execute all the actions for each server in the yaml file.
    Actions:
        - Server Login
        - Verify if the server is already claimed
        - Get Device Id, Security Token
        - Server Logout
    """
    with open("ucs_hosts.yml", "r", encoding="utf-8") as file:
        server_data = yaml.safe_load(file)
        for server in server_data:
            host = server["host"]
            username = server["username"]
            password = server["password"]
            base_url = f"https://{host}/"
            # Add a condition for connection failure
            # We need to skip for connection failures.
            out_cookie = ucs_login(base_url, username, password)
            connection_info = get_connection_state(base_url, out_cookie)
            if connection_info["AccountOwnershipState"] == "Claimed":
                intersight_account = connection_info["AccountOwnershipName"]
                print(
                    f"Server {host} claimed under Intersight Account: {intersight_account}"
                )
                out_status = ucs_logout(base_url, out_cookie)
                print(f"Log out: {out_status}")
                continue
            device_id = get_device_identifier(base_url, out_cookie)
            device_token = get_security_tokens(base_url, out_cookie)
            print(f"DeviceIdentifier: {device_id}, Token: {device_token}")
            out_status = ucs_logout(base_url, out_cookie)
            print(f"Log out: {out_status}")


def main():
    """
    Main function to trigger the workflow
    """
    # Suppress Certificate warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    workflow()


if __name__ == "__main__":
    main()
