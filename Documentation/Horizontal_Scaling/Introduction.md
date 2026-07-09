# Pod Scaling — ZeroTrustForwardProxy

---

- [Architecture](#arch)

<a name=arch></a>
## Architecture
*-* Scaling means running proxy process in multiple pods.
*-* DLP, TSS, proxy are not broken into seperate services:

** if we break DLP, TSS and proxy into 3 separate pods there will be a latency on every request, due to sending requests over kubernets network between pods(~0.5–2 ms). For time being we will be staying with the monolith(proxy+DLP+TSS=1pod) that is one proxy containing DLP, TSS but later we will plan to break into multiple pods.
```
NLB
 ├── Pod 1  [TLS + Policy + DLP]
 ├── Pod 2  [TLS + Policy + DLP]
 └── Pod 3  [TLS + Policy + DLP]
```

