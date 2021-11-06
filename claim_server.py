#!/usr/bin/env python3
"""
Purpose:
    Check Server Connectivity on Port 22
    Login to UCS servers
    Get the Device ID and Security Token
    Claim Server in Intersight
    Logout
Author: Sandeep Kumar
"""
import time
import os
from time import perf_counter
import socket
import xml.etree.ElementTree as ET
import json
import yaml
import requests
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv
from intersight_auth import IntersightAuth


load_dotenv()


class dc:
    @staticmethod
    def ucs_login(base_url, username, password):
        """
        Login to UCS Server.
        Get outCookie for subsequent requests.
        * Update function with connection failure code.
        """
        url_path = "nuova"
        url = base_url + url_path
        payload = f"<aaaLogin inName='{username}' inPassword='{password}'></aaaLogin>"
        headers = {"Content-Type": "application/xml"}
        response = requests.request(
            "POST", url, headers=headers, data=payload, verify=False
        )
        print(response.text)
        xml_root = ET.fromstring(response.content)
        out_cookie = xml_root.attrib["outCookie"]
        return out_cookie

    @staticmethod
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

    @staticmethod
    def get_systems(base_url, out_cookie):
        """
        Get Device Claim Status
        """
        url_path = "connector/Systems"
        url = base_url + url_path
        payload = {}
        headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        return response.json()[0]

    @staticmethod
    def get_device_identifier(base_url, out_cookie):
        """
        Get Device Identifier
        """
        url_path = "connector/DeviceIdentifiers"
        url = base_url + url_path
        payload = {}
        headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        device_id = response.json()[0]["Id"]
        return device_id

    @staticmethod
    def get_security_tokens(base_url, out_cookie):
        """
        Get Security Token Value
        """
        url_path = "connector/SecurityTokens"
        url = base_url + url_path
        payload = {}
        headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        if isinstance(response.json(), list):
            token = response.json()[0]["Token"]
            return token
        if isinstance(response.json(), dict):
            if response.json()["code"] == "InvalidRequest":
                message = response.json()["message"]
                return message

    @staticmethod
    def update_dc_config(out_cookie, host, url_path, payload_dict):
        url = f"https://{host}/connector/{url_path}"
        headers = {"ucsmcookie": f"ucsm-cookie={out_cookie}"}
        response = requests.put(
            url, headers=headers, data=json.dumps(payload_dict), verify=False
        )
        print(response.status_code)
        print(response.text)
        return response.json()[0]

    @staticmethod
    def get_claim_codes(
        host=None,
        out_cookie=None,
        base_url=None,
        system_info=None,
        dc_payload=None,
        dns=False,
        ntp=False,
        proxy=False,
        dns_payload=None,
        ntp_payload=None,
        proxy_payload=None,
    ):
        if system_info["AdminState"] == False:
            # Enable Device Connector
            print("DC Disabled, Enabling DC")
            url_path = "Systems"
            response = dc.update_dc_config(out_cookie, host, url_path, dc_payload)
            print(f'Enabled DC: {response["AdminState"]}')

            # Update DNS Info
            if dns is True:
                url_path = "CommConfigs"
                dns_update = dc.update_dc_config(
                    out_cookie, host, url_path, dns_payload
                )
                print(f"Added DNS Config: {dns_update}")

            # Update NTP Info
            if ntp is True:
                url_path = "CommConfigs"
                ntp_update = dc.update_dc_config(
                    out_cookie, host, url_path, ntp_payload
                )
                print(f"Added NTP Config: {ntp_update}")

            # Update proxy Info
            if proxy is True:
                url_path = "HttpProxies"
                proxy_update = dc.update_dc_config(
                    out_cookie, host, url_path, proxy_payload
                )
                print(f"Added Proxy Config: {proxy_update}")

            # Wait while Establishing connection
            dc_conn_state = response["ConnectionState"]
            while dc_conn_state == "Establishing Connection":
                time.sleep(2)
                print("Waiting for Connection to Establish")
                system_info = dc.get_systems(base_url, out_cookie)
                print(system_info["ConnectionState"])
                if system_info["ConnectionState"] != "Establishing Connection":
                    dc_conn_state = system_info["ConnectionState"]
            # Admin state True, Connection != "Establishing Connection"
            if (
                system_info["AdminState"] is True
                and system_info["ConnectionState"] == "Connected"
            ):
                if system_info["AccountOwnershipState"] == "Not Claimed":
                    print("Device not Claimed. Getting Claim Codes")
                    device_id = dc.get_device_identifier(base_url, out_cookie)
                    device_token = dc.get_security_tokens(base_url, out_cookie)
                    print(
                        f"Claim Codes: \nDevice Id: {device_id},  Claim Code: {device_token}"
                    )
                    claim_codes = {}
                    claim_codes["device_id"] = device_id
                    claim_codes["device_token"] = device_token
                    return claim_codes
                elif system_info["AccountOwnershipState"] == "Claimed":
                    # Device Already Claimed Condition
                    print(
                        f'{host} claimed in Intersight account {system_info["AccountOwnershipName"]}'
                    )
        elif system_info["AdminState"] is True:
            # While Establishing connection, wait
            print("DC already Enabled")

            # Configure NTP, DNS
            # Update DNS Info
            if dns is True:
                url_path = "CommConfigs"
                dns_update = dc.update_dc_config(
                    out_cookie, host, url_path, dns_payload
                )
                print(f"Added DNS Config: {dns_update}")

            # Update NTP Info
            if ntp is True:
                url_path = "CommConfigs"
                ntp_update = dc.update_dc_config(
                    out_cookie, host, url_path, ntp_payload
                )
                print(f"Added ntp Config: {ntp_update}")

            # Update proxy Info
            if proxy is True:
                url_path = "HttpProxies"
                proxy_update = dc.update_dc_config(
                    out_cookie, host, url_path, proxy_payload
                )
                print(f"Added Proxy Config: {proxy_update}")

            dc_conn_state = system_info["ConnectionState"]
            while dc_conn_state == "Establishing Connection":
                time.sleep(2)
                print("Waiting for Connection to Establish")
                system_info = dc.get_systems(base_url, out_cookie)
                print(system_info["ConnectionState"])
                if system_info["ConnectionState"] != "Establishing Connection":
                    dc_conn_state = system_info["ConnectionState"]

            # Admin state True, Connection != "Establishing Connection"
            if system_info["ConnectionState"] == "Connected":
                if system_info["AccountOwnershipState"] == "Not Claimed":
                    # Get Claim Codes
                    print("Device not Claimed. Getting Claim Codes")
                    device_id = dc.get_device_identifier(base_url, out_cookie)
                    device_token = dc.get_security_tokens(base_url, out_cookie)
                    print(f"Device Id: {device_id},  Claim Code: {device_token}")
                    claim_codes = {}
                    claim_codes["device_id"] = device_id
                    claim_codes["device_token"] = device_token
                    return claim_codes
                elif system_info["AccountOwnershipState"] == "Claimed":
                    # Device Already Claimed Condition
                    print("")
                    print(
                        f'Device {host} already claimed in Intersight account {system_info["AccountOwnershipName"]}'
                    )
            elif (
                system_info["AdminState"] is True
                and system_info["ConnectionState"] != "Establishing Connection"
                and system_info["ConnectionState"] != "Connected"
            ):
                # Device Internet Connectivity Issues. Print Error
                print(
                    f'{system_info["ConnectionState"]} : {system_info["ConnectionStateQualifier"]}'
                )


def claim_server(server):
    """
    Execute all the actions for server in the yaml file.
    Actions:
        - Server Login
        - Verify if the server is already claimed
        - Update DNS, NTP, Proxy Info
        - Get Device Id, Security Token
        - Server Logout
    """
    host = server["host"]
    username = server["username"]
    password = server["password"]
    base_url = f"https://{host}/"
    config_dns = server["config_dns"]
    config_ntp = server["config_ntp"]
    config_proxy = server["config_proxy"]

    # Define Device Connector, dns, NTP payloads
    enable_dc_payload = {
        "AdminState": True,
        "ReadOnlyMode": server["read_only"],
    }
    dns_payload_dict = {
        "NameServers": server["name_servers"],
        "DomainName": server["domain_name"],
    }
    ntp_payload_dict = {"NtpServers": server["ntp_servers"]}

    proxy_payload_dict = server["proxy_payload"]

    # Check server connectivity
    if server_connection(host):
        # Get out_cookie for subsequent requests
        out_cookie = dc.ucs_login(base_url, username, password)
        print(out_cookie)

        # Get DC(Device Connector) Systems Info
        system_info = dc.get_systems(base_url, out_cookie)
        print(system_info)

        # Get claim codes if device not claimed
        claim_codes = dc.get_claim_codes(
            host=host,
            out_cookie=out_cookie,
            base_url=base_url,
            system_info=system_info,
            dc_payload=enable_dc_payload,
            dns=config_dns,
            ntp=config_ntp,
            proxy=config_proxy,
            dns_payload=dns_payload_dict,
            ntp_payload=ntp_payload_dict,
            proxy_payload=proxy_payload_dict,
        )
        print(claim_codes)

        device_id = claim_codes["device_id"]
        device_token = claim_codes["device_token"]
        claim_status = intersight_claim_device(device_token, device_id)
        if claim_status == "200":
            print(f"Claimed Server {host} Successfully in Intersight")
        else:
            print(f"There was an issue claiming the Server: {claim_status}")

        # Device Logout
        logout_status = dc.ucs_logout(base_url, out_cookie)
        print(f"Log Out Status: {logout_status}")
    else:
        print(f"{host} not reachable")


def server_connection(server: str, port: int = 443, timeout=3):
    """Check server connectivity"""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
    except OSError as error:
        return False
    else:
        s.close()
        return True


def intersight_claim_device(security_token, serial_number):
    """
    Claim server in Intersight
    """
    # Create an AUTH object
    auth = IntersightAuth(
        secret_key_filename="./SecretKey.txt", api_key_id=os.getenv("api_key_id")
    )
    url = "https://intersight.com/api/v1/asset/DeviceClaims"
    payload = {"SecurityToken": security_token, "SerialNumber": serial_number}
    headers = {"Content-Type": "application/json"}
    print("Sending Info to Intersight")
    response = requests.request(
        "POST", url, auth=auth, headers=headers, data=json.dumps(payload)
    )
    print("Got Response from Intersight")
    if (
        response.status_code == 401
        and response.json()["code"] == "AuthenticationFailure"
    ):
        print(response.json()["message"])
        return response.json()["message"]
    elif response.status_code == 200 and response.json()["Results"]:
        return response.status_code


def main():
    """
    Main function to execute the code
    """
    start_time = perf_counter()
    # Suppress TLS Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Get Claim Codes
    filename = "ucs_hosts.yml"
    with open(filename, "r", encoding="utf-8") as file:
        server_data = yaml.safe_load(file)

    # Claim servers using threads
    with concurrent.futures.ThreadPoolExecutor() as executor:  # max_workers=x
        executor.map(claim_server, server_data)

    # Print how long it took for script execution
    end_time = perf_counter()
    print(f"It took {end_time - start_time :0.4f} second(s) to complete.")


if __name__ == "__main__":
    main()
