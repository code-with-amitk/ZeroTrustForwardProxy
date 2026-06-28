
# Kubernetes
kubernets is used for creating multiple pods, running proxy inside pods and directing the traffic to each of pod. We choose for creating and running pods is kubernets. Kubernets have a master/controller node. Pods run inside worker node. pod is smallest deployable unit. 1 Pod can host multiple containers. 1 container should run 1 application.

- [What is kubernets](https://code-with-amitk.github.io/System_Design/Concepts/Kubernets/Introduction.html)
- [How kubernets helps in scaling?](https://code-with-amitk.github.io/System_Design/Concepts/Kubernets/Introduction.html)
- [Why choosen kubernets over k3s]()

## Process
- Create a docker image using Dockerfile for proxy
- Create kubernets manifests deployment of docker image  