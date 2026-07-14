- [AST](#ast)
- [Memory Representation for AST of Tenant](#mr)
  - [Present Design](#pd)
    - [Issues](#i1)
- Proposed designs
  - [Design 1(App based AST)](#p1)
  - [Design 2(App based AST)](#p2)
- [Runtime flow](#rf)

<a name=ast></a>
## Abstract Syntax Tree
[1st Read. How rule is represented in AST](https://github.com/code-with-amitk/Code-examples/blob/master/DS_Questions/Data_Structures/Trees/AST_Abstract_Syntax_Tree.md)
 
<a name=mr></a>
## Memory Representation for AST of Tenant

<a name=pd></a>
### Present Design

```c
Rule1
    user=alice
    App=firefox
    action=browse
    policyAction=continue

Rule1-AST (0x400)
              &&
            /    \
          &&    policyAction=continue
            \
       |---------|----------|
      ==        ==          ==
    /    \    /    \        /\
user   alice action browse App firefox

Rule2-AST (0x700)
    user=bob
    App=box
    action=Download
    policyAction=block

Each rule have its own AST.

Tenant:
    Rule1-AST -----> Rule2-AST -----> Rule3 -----> Rule4
```
Each rule have its own AST and tenant AST is collection of AST

<a name=i1></a>
#### Issues

**1. Time Complexity is large. O(number of rules)**

- Finding a matching rule Rule takes `O(number of rules)`.
- Suppose there are 500 rules(490 box, 9 firefox, 1 chrome). Then Chrome request comes in then all rules are checked, Most of these are Box rules. Waste of CPU.
- Everytime parse giant AST

<a name=pd></a>
### Proposed designs

<a name=pd1></a>
#### Design 1(App based AST)
Group rules based on App Name. 100's of different App rules are skipped.

```c
Rule1: App=jira, user=alice, block
Rule2: App=jira, user=bob, allow
Rule3: App=box, action=upload, Inspect
Rule4: App=box, action-download, block

                 Application        //App AST. O(nlogn)
             /                 \
         Jira                  Box
      /          \         /         \
 Rule1       Rule2     Rule3      Rule4
```

<a name=d2></a>
### Design 2A(App unordered_map)
- Instead of App based AST. Create HashMap of App names which points to AST of Apps and rules
- Time complexity: O(1)

```c
unordered_map<string, Node*> ApplicationMap
ApplicationMap["Jira"]  << O(1)
```

<a name=rf></a>

## Runtime flow
```
HTTP packet arrives (:8080)
        │
        ▼
proxy.evaluate()
        │
        ├─① auth.ExtractAuthorizationnHeader(r)
        │     Read Bearer JWT
        │     jwt.ValidateJWT → claims.TenantID (int64)
        │     strict mode: reject if /var/ztfp/policies/{id}/policy.db missing
        │     dev mode: tenant_id=0 → default_tenant_id (e.g. 1)
        │
        │     Result: tenantID = 1, user = "alice"
        │
        ├─② domain = r.Host / URL host   (e.g. "www.facebook.com")
        │     method = r.Method          (e.g. "GET")
        │
        └─③ s.Policy.Decide(tenantID, domain, method)
              │
              ▼
        TenantPolicyRegistry.Decide(1, "www.facebook.com", "GET")
              │
              ▼
        TenantPolicyFor(1)   ← lookup tenant_id → *TenantPolicy
              │
              ├─ HIT:  cache[1] → *TenantPolicy → tp.Decide(...)
              │
              └─ MISS: load /var/ztfp/policies/1/policy.db
                       LoadFromDB → buildAST → insert cache[1] → Decide(...)
```