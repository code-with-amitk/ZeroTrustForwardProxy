- Bypass PAC, nsclient scenarios
  - [Uninstall nsclient, Remove PAC file](#s1)
  - [Install new Browser(Brave)](#s2)
  - [curl HTTP GET](#s3) 
- PAC, nsclient Both present
  - [Why nsclient needed, if PAC is present](#why)
  - [How traffic sterring happen when both are present](#how) 


## Bypass PAC, nsclient

<a name=s1></a>
### 1. Uninstall nsclient, PAC installed browser
- Organizations have hardend the laptops using following methods:
- Admin password needed for:
  - Uninstalling/Installing anything
  - Changing the Proxy Settings on Browser(here PAC file lives)

#### nsclient crash
- nsclient cannot be uninstalled because it needs admin password, and tenant want traffic should always steer via nsclient for inspection. What should be done if nsclient crashes?

**2 Approaches:** Based on Tenant's security posture
1. FAIL CLOSE(Banks/Government): Block traffic if the Client cannot enforce security.
2. FAIL SAFE(Retail/Manufacturing/General Enterprise): Allow traffic if the Client fails, prioritizing availability over security.

<a name=s2></a>
### 2. Install new Browser(Brave)
- New installation require(Admin Password) which not provided to user, new browser cannot be installed

<a name=s3></a>
### 3. curl HTTP GET
- Since nsclient is always enabled on system, if user does HTTP GET via curl, it will land on nsproxy.

## PAC, nsclient Both present

<a name=why></a>
### Why nsclient needed, if PAC is present
- In somecases Netskope Client installation not possible:
  - Contractors BYOD (Bring Your Own Device):
    - Having legacy/unsupported OS for nsclient
    - Clashing softwares installed wrt nsclient

<a name=how></a>
### How traffic sterring happen PAC+nsclient
nsclient and PAC are aware of each other, and the nsclient avoids re-steering traffic that is already destined for Netskope style proxy by PAC.
