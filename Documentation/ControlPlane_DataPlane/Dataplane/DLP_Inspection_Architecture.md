
- [Phase 1 — Monolith (current)](#pd)
    - [Flow](#ph1flow)
- [Phase 2 — Separate `dlpd`, `proxy` pod in Kubernetes](#ph2)
    - [Flow](#ph2flow)
    - [Very large file (10 GiB) — async spool, not inline sync](#lf)
        - [What to scale when files grow](#scale)
    - [Phase 2 open item (must validate before moving to Phase 3)](#validate)
- [Phase 3 — On-demand DLP + presigned upload](#ph3)
    



<a name=pd></a>

## Phase 1 — Monolith (current)
- nsproxy does TLS Interception
- nsproxy recieve file for inspection, shares on location. DLP reads from same location
- Latency = lowest

<a name=ph1flow></a>

### Flow
```mermaid
sequenceDiagram
    participant Client
    participant ZTFP as ztfp pod<br/>(single process)
    participant Insp as inspector package<br/>in-process
    participant Up as Upstream

    Client->>ZTFP: POST upload (MITM cleartext)
    ZTFP->>ZTFP: Policy Decide(tenant_id, domain)
    ZTFP->>Insp: InspectRequest(body stream)
    Note over Insp: Read max 1 MiB into []byte<br/>NOT on disk
    Insp->>Insp: regex scan buffer
    Insp-->>ZTFP: violations or OK
    ZTFP->>Up: MultiReader(1 MiB scanned + rest streamed)
    Up-->>Client: response path (same pattern for responses)
```

<a name=ph2></a>

## Phase 2 — Separate `dlpd`, `proxy` pod in Kubernetes

- Scale DLP independently. TLS stays on **`ztfp`**; **`dlpd`** never terminates client TLS.
- When proxy and DLP run in **two Kubernetes Deployments**, context crosses the **pod network** via gRPC; **large file bytes** should use **shared spool**, not 10 GiB pod-to-pod streaming.

<a name=ph2flow></a>

### Flow
```mermaid
sequenceDiagram
    participant Client
    participant ZTFP as ztfp pod<br/>TLS + policy + tee
    participant DLPD as dlpd pod<br/>inspect workers
    participant Up as Upstream

    Client->>ZTFP: HTTPS upload (MITM cleartext)
    ZTFP->>ZTFP: Policy Decide → inspect required
    ZTFP->>ZTFP: Peek 4 KiB + file-type route
    loop Chunk stream e.g. 64 KiB
        ZTFP->>DLPD: gRPC InspectChunk(tenant, meta, bytes, eof)
        DLPD-->>ZTFP: partial verdict / continue
    end
    DLPD-->>ZTFP: final verdict ALLOW/BLOCK
    alt ALLOW
        ZTFP->>Up: forward (already streaming or replay from spool)
    else BLOCK
        ZTFP-->>Client: block page / reset
    end
```

<a name=lf></a>

### Very large file (10 GiB) — async spool, not inline sync
- **Question:** Is 10GB file recieved by 2 proxy pods(5 GiB + 5 GiB)?
    - **No** for one upload. You do **not** shard one HTTP body across two `ztfp` replicas. 
- **Question:** How much data can a **single pod** “receive”?
    - Kubernetes does **not** define a “max upload per pod.” Limits come from **memory**, **ephemeral storage / PVC size**, **CPU**, **connection duration**, and **node/network bandwidth**

**Flow** 

- ztfp accepts file, writes to **object store / spool PVC** (streaming write, not 10 GiB RAM)
- ztfp returns **hold** (block until scan), **429**, or **allow + async scan** per policy
- ztfp calls `dlpd.SpoolScan(spool_uri, metadata)`
- dlpd reads from storage in workers; may take minutes
- Verdict → callback / poll; ztfp already allowed with alert or blocked mid-upload if policy requires

```mermaid
flowchart LR
    subgraph good1 [Pattern A — spool recommended]
        C[Client] --> Z[ztfp pod]
        Z --> S[(PVC / S3 spool)]
        D[dlpd pod] --> S
        Z -->|SpoolScan gRPC| D
    end
```

<a name=scale></a>

#### What to scale when files grow
- `ztfp`, `dlpd` Deployment replicas
- Spool PVC size / S3 bucket + lifecycle

<a name=validate></a>

### Phase 2 open item (must validate before moving to Phase 3)

Before committing to zftp vs client→S3, **benchmark in your cluster**:

- Send 10GB file to zftp->spool->dlp. Check
    - MB/s reached on dlp
    - pod restarts.
    - spool deletes
    - Load test
    - **chunked gRPC** at 128 MiB vs 1 GiB — observe memory and gRPC message limits.
    - Timeout at NLB, upload duration

<a name=ph3></a>

## Phase 3 — On-demand DLP + Seperate Microservices

- Remove **multi-gigabyte byte paths through the proxy pod**. 
- Traffic Processor(TP) terminates the HTTPS.
** TP will do inline file type detection from 1st 4KB bytes and send file to be stored on object store (S3/Ceph/MinIO)
** TP will also find metadata(and create a event message) from http header and will pass meta data to policy engine for policy inspection.
- Policy engine(PE) will compare AST(Abstract Syntax tree) with event message and inform DLP inspection in requrired
- Connector will send object_id to DLP(Seperate Standalone VM service) for inspection.
** DLP informs negative(ie file does have leaks)
- Connector sends object_id to Forwarder, which reads file from object store and sends the file for upload to box.com
- Multiple pods scale independently, every pod has different scaling creteria.
```
PAC Gateway: Traffic processing may be CPU/network/TLS bound
DLP: CPU-heavy
Policy engine: memory/cache bound
Forwarder: Bandwidth/connection bound
```

<img src=phase-3_ondemandDLP_microservices.png width=1400/>

### File-type detection (first 4 KiB)

- Policy may vary based on file type. That will be helpful for DLP/TSS for scanning the file.

