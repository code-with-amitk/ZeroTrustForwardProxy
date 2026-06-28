Manifests

- [Deployed manifests](#manifests)
-- [deployment.yaml](#deployment)
-- [service.yaml](#service)
-- [hpa.yaml](#hpa)
-- [configmap-config.yaml](configmap)
- [Helm chart structure (production)](#helm)


## Kubernets manifests
- These are Kubernetes manifest files written in YAML, used to tell Kubernetes how to deploy, manage, and scale your container image.
- Only deployment.yaml and service.yaml are mandatory to deploy and access your container.
- Rest are optional tools used to handle scaling, security, configuration, and monitoring.

<a href=manifests></a>
### Deployed manifests

```yaml
k8s/
├── namespace.yaml          # ztfp namespace
├── secret-ca.yaml          # ca.crt + ca.key (same across all environments)
├── configmap-policy.yaml   # policy.yaml content
├── configmap-config.yaml   # config.yaml (listen_addr, metrics_addr, etc.)
├── configmap-blockpage.yaml# block.html template
├── deployment.yaml         # Deployment with 3 replicas, mounts, probes
├── service.yaml            # type=LoadBalancer (provisions NLB on AWS)
├── hpa.yaml                # HorizontalPodAutoscaler — scale on CPU 70%
└── servicemonitor.yaml     # Prometheus ServiceMonitor for scraping :9090
```

<a href=deployment></a>
#### deployment.yaml
[What is deployment.yaml](https://code-with-amitk.github.io/System_Design/Concepts/)

```yaml
kind: Deployment
spec:
  replicas: 3               # Start 3 replicas for proxy
  selector: 
    matchLabels:
      app: ztfp
  strategy:
    type: RollingUpdate     # Keep running 1 proxy, until other comes up
  template:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port:   "9090"
        prometheus.io/path:   "/metrics"
      containers:           # Container to be deployed
        - name: proxy
          image: ztfp:latest
          imagePullPolicy: IfNotPresent
          args: ["--config", "/etc/ztfp/config.yaml"]
          ports:
            - name: proxy
              containerPort: 8080
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
          resources:                # Start with this CPU, Memory
            requests:
              cpu:    "500m"
              memory: "512Mi"
            limits:
              cpu:    "2000m"
              memory: "2Gi"

          # Liveness: restart the pod if the process is completely stuck.
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3

          # Readiness: hold traffic until the proxy listener is fully bound.
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
            initialDelaySeconds: 3
            periodSeconds: 5
            failureThreshold: 3

          volumeMounts:
            # Main config file.
            - name: config
              mountPath: /etc/ztfp/config.yaml
              subPath: config.yaml
              readOnly: true
            - name: policy
              mountPath: /etc/ztfp/policy.yaml
              subPath: policy.yaml
              readOnly: true
            - name: ca
              mountPath: /etc/ztfp/ca
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: ztfp-config
        - name: policy
          configMap:
            name: ztfp-policy
        - name: ca
          secret:
            secretName: ztfp-ca
```

<a href=service></a>
#### service.yaml
[What is service.yaml](https://code-with-amitk.github.io/System_Design/Concepts/)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ztfp
  namespace: ztfp
  labels:
    app.kubernetes.io/name: ztfp
  annotations:
    # AWS NLB — use Network Load Balancer for raw TCP (required for CONNECT proxy traffic).
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  selector:
    app: ztfp
  ports:
    - name: proxy
      port: 8080
      targetPort: proxy
      protocol: TCP
    - name: metrics
      port: 9090
      targetPort: metrics
      protocol: TCP
```

<a href=hpa></a>
#### hpa.yaml
[What is hpa.yaml](https://code-with-amitk.github.io/System_Design/Concepts/)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ztfp
  namespace: ztfp
  labels:
    app.kubernetes.io/name: ztfp
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ztfp
  minReplicas: 3
  maxReplicas: 50
  metrics:
    # Scale on CPU first — cheap, always available.
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    # Scale on memory pressure to catch connection-heavy workloads.
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Pods
          value: 4
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 120
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
```

<a href=configmap></a>
#### configmap-config.yaml
[What is configmap.yaml](https://code-with-amitk.github.io/System_Design/Concepts/)

```yaml
# Configuration used by proxy
apiVersion: v1
kind: ConfigMap
metadata:
  name: ztfp-config
  namespace: ztfp
  labels:
    app.kubernetes.io/name: ztfp
data:
  config.yaml: |
    listen_addr: ":8080"
    metrics_addr: ":9090"
    policy_file: "/etc/ztfp/policy.yaml"
    ca_cert_file: "/etc/ztfp/ca/ca.crt"
    ca_key_file:  "/etc/ztfp/ca/ca.key"
    idle_conn_timeout: 90s
    max_idle_conns: 512
    max_idle_conns_per_host: 128
    request_timeout: 30s
    max_inspect_body_bytes: 1048576
```

<a href=helm></a>
### Helm chart structure (production)

```yaml
helm/ztfp/
├── Chart.yaml
├── values.yaml             # replicaCount, image.tag, resources, etc.
└── templates/
    ├── deployment.yaml
    ├── service.yaml
    ├── hpa.yaml
    ├── configmap.yaml
    ├── secret.yaml
    └── servicemonitor.yaml
```

Deploy with:

```bash
helm install ztfp ./helm/ztfp \
  --set replicaCount=3 \
  --set image.tag=v1.2.0 \
  --set resources.limits.cpu=4000m \
  --set resources.limits.memory=4Gi
```