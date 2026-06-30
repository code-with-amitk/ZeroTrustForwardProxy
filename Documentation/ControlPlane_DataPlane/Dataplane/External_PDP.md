
## External PDP(Policy Decision Point)
**Problem**

10000s of tenants, each with complex rule sets(500+ rules), are loading Abstract Syntax Trees (ASTs) into the memory(RAM) of a single application which is creating huge memory pressure(RAM growing) since policy engine performs hot reload of tenant's AST into memory whenever packet processing from tenant is needed. 

### What is PDP
- PDP is industry-standard solution to decouple authorization logic from your core application, effectively offloading the memory and CPU burden.
- Application can be divided into 2 components:
-- Policy Enforcement Point (PEP): This is go current application. It intercepts user requests and asks, "Is this allowed?"
-- Policy Decision Point (PDP): An external, dedicated service that holds the policy data, evaluates it against incoming requests, and returns a simple "Permit" or "Deny" decision to the PEP.
```
--HTTP--> [PEP]         [PDP] 
            --event_msg-->
            <--allow--
```

#### Benefits
1. Scalability: You can scale the PDP independently of your application. If tenant load increases, you can add more instances of the PDP to handle the policy evaluation traffic without impacting your application's core performance.
2. Memory Offloading: The heavy lifting (loading 500 rules per tenant, building the ASTs, and evaluating them) happens inside the memory space of the PDP service, not your main application.
3. Caching: A PDP can intelligently cache evaluation results. If multiple users from the same tenant request the same resource, the PDP returns the result from its cache