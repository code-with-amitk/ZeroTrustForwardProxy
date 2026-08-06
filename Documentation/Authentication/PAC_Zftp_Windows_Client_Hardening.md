- Bypass PAC, zftp Window's Client scenarios
  - [Uninstall zftp Window's Client, Remove PAC file](#s1)
  - [Install new Browser(Brave)](#s2)
  - [curl HTTP GET](#s3) 
- PAC, zftp Window's Client Both present
  - [Why zftp Window's Client needed, if PAC is present](#why)
  - [How traffic sterring happen when both are present](#how) 


## Bypass PAC, zftp Window's Client

<a name=s1></a>
### 1. Uninstall zftp Window's Client, PAC installed browser
- Organizations have hardend the laptops using following methods:
- Admin password needed for:
  - Uninstalling/Installing anything
  - Changing the Proxy Settings on Browser(here PAC file lives)

#### zftp Window's Client crash
- zftp Window's Client cannot be uninstalled because it needs admin password, and tenant want traffic should always steer via zftp Window's Client for inspection. What should be done if zftp Window's Client crashes?

**2 Approaches:** Based on Tenant's security posture
1. FAIL CLOSE(Banks/Government): Block traffic if the Client cannot enforce security.
2. FAIL SAFE(Retail/Manufacturing/General Enterprise): Allow traffic if the Client fails, prioritizing availability over security.

<a name=s2></a>
### 2. Install new Browser(Brave)
- New installation require(Admin Password) which not provided to user, new browser cannot be installed

<a name=s3></a>
### 3. curl HTTP GET
- Since zftp Window's Client is always enabled on system, if user does HTTP GET via curl, it will land on nsproxy.

## PAC, zftp Window's Client Both present

<a name=why></a>
### Why zftp Window's Client needed, if PAC is present
- In somecases Windows Client installation not possible:
  - Contractors BYOD (Bring Your Own Device):
    - Having legacy/unsupported OS for zftp Window's Client
    - Clashing softwares installed wrt zftp Window's Client

<a name=how></a>

### How traffic sterring happen PAC+zftp Window's Client
zftp Window's Client and PAC are aware of each other, and the zftp Window's Client avoids re-steering traffic that is already destined for forward style proxy by PAC.
