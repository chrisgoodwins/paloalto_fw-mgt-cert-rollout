# paloalto_fw-mgt-cert-rollout
This is a menu-driven script that automates the entire process for pushing management certificates to Palo Alto Networks firewalls throughout the enterprise.

### Features
- Generate CSRs in bulk
- Integrates with Microsoft ADCS CA server, so you can easily have your CSRs signed
- If no PKI exists, allows you to create your own CA, or use one from Panorama or firewall
- Deploy signed certificates to firewalls in bulk
- Create and apply SSL/TLS Certificate profiles in bulk
- Send bulk commits
### Menu Interface
```
--------------------------------------------------------------------------------
Choose an option below to add certificate attributes and crypto settings,
and add addresses via the terminal and/or CSV file. Choose exit when finished...
--------------------------------------------------------------------------------

1.  Add/Modify Attributes
2.  Modify Crypto Settings
3.  Modify Expiration
4.  Clear Attributes/Crypto Settings
5.  Print Attributes/Crypto Settings
6.  Input Addresses
7.  Create Certificate Signing Requests
8.  Interface with Enterprise CA Server
9.  Push Signed Certificates to Firewalls
10. Create/Apply Cert Profiles to Firewalls
11. Validate/Commit Firewalls
12. Exit

--------------------------------------------------------------------------------

Enter your choice:
```

### Usage and Workflow
1) Generate CSRs - You can do this in two ways: by adding attributes and crypto settings through the menus in the script, or by populating a CSV with the values corresponding to their firewall address. You can also use a combo of both. If you specify the attributes and crypto settings using the menus, you will need to provide a list of addresses using the menus as well. If you provide attributes and crypto setting through a CSV file, the address list should be apart of the CSV.
2) Sign your CSRs - The script supports a number of ways to do this...
    - If a PKI exists, and Microsoft ADCS is in use, the script integrates directly with it. It supports both basic and NTLM authentication. It also supports the use of CA manager approval. If no manager approval is necessary, then it downloads the signed PEM certs. If CA manager approval is necessary, then it saves the request ID information for each cert request. Once pending requests are approved, you can enter the script's CA server menu again and  it will automatically recognize that it has cert requests pending, so it will download the signed PEM certs for you.
    - If a PKI exists, but doesn't use MS ADCS, you will need to manually export the CSRs from the 'PAN-FW-CSRs' folder, have them signed by your CA, then return the certs in pem format to the 'PAN-FW-PEMs' folder to continue through the workflow.
    - If no PKI exists, you can either create a self-signed CA within this script, or you can create one on a Panorama or firewall, or any other device. If a CA is created outside of this script, just save the CA cert with the private key in pem format. They can either be saved as one .pem file or separately as .crt and .key files. They would need to be saved to a folder named 'PAN-CA-Cert' in order for the script to recognize them.
3) Push signed certs to firewalls - Just choose the menu option to do so, the script will handle this for you.
4) Choose the option to create and apply the SSL/TLS cert profiles. This will also associate the firewall's cert to the profile and apply the profile.
5) Commit the firewalls - This can be done using the menu option in the script. You will have the option to step through validation on each, or push and pray.

Note: When generating CSRs, you will have the ability to provide attribute information. This can either be done with a CSV file, or the info can be provided through menus within this script. You'll want to use a CSV file if the attributes differ among the firewalls. If the attributes are the same across all firewalls, or you don't want to add attributes, then you should use the menus. The CN field within certificates will be the IP/FQDN that you provide either within the menu, or in the CSV file.


If you choose to use a CSV file, the format should be the following for each entry:

IP/FQDN, country, state, locality, organization, [department], email, [hostname], [IP], [alt email], algorithm, bits, digest, expiration

--Attributes with brackets have an option to add multiples, be sure to enclose comma-separated entries with brackets if there are multiples--
