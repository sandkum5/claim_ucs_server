# Claim_Server
- Check Server Connectivity on Port 443.
- If Device Connector is enabled, get Cisco UCS Server Device Connector Claim Codes.
- If Device Connector is disabled, enable Device Connector, update DNS, NTP, Proxy info and get the claim codes. 
- If the device is already claimed, print the Server IP and the Intersight Account under which its claimed. 
- Else, get the claim codes and claim the Server in Intersight. 

### Pre-requisites
- intersight_auth.py Module
- Intersight API Keys
  - Intersight api_key_id updated in .env file. 
  - Intersight API SecretKey.txt file. 
- ucs_hosts.yml file updated with Server IP's, Credentials, DNS, NTP, Proxy Info. 

```
$ python3 claim_server.py
```
