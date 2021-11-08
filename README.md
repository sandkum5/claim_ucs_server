# Claim_Server
- Checks Server Connectivity on Port 443.
- If Device Connector is enabled, get Cisco UCS Server Device Connector Claim Codes.
- If Device Connector is disabled, enable Device Connector, update DNS, NTP, Proxy info and get the claim codes. 
- If the device is already claimed, print the Server IP and the Intersight Account under which its claimed. 
- Else, get the claim codes and claim the Server in Intersight. 

### Pre-requisites
- Python Modules
  - pyyaml 
  - python-dotenv
- Command to Install Python Modules: pip3 install pyyaml python-dotenv
- intersight_auth.py Module
- Intersight API Keys
  - Intersight api_key_id updated in .env file. 
  - Intersight API SecretKey.txt file. 
- Update ucs_hosts.yml file with Server IP's, Credentials, DNS, NTP, Proxy Info. 

```
$ python3 claim_server.py
```
