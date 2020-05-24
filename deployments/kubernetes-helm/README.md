# Kubernetes / Helm Deployment Template for the CSP violation collector

## TL;DR;

```console
$ helm upgrade csp-collector kubernetes-helm --values custom-values.yaml --install
```

## Introduction

This chart deploys a Content Security Policy violation collector from
https://github.com/jacobbednarz/go-csp-collector/

Using the [kubernetes-helm/values.yaml][1] file create a custom-values.yaml override
with just the changed values then run the command above. Example:

```yaml
replicaCount: 2
custom:
  filterlist: "custom.filter.list"

ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class:            nginx
    certmanager.k8s.io/cluster-issuer:      'my-key-name'
    certmanager.k8s.io/acme-challenge-type: 'dns01'
    certmanager.k8s.io/acme-dns01-provider: 'route53'
    nginx.ingress.kubernetes.io/force-ssl-redirect:     'true'
  hosts:
    - csp-reports.example.com
  tls:
   - secretName: csp-reports.example.com-tls
     hosts:
       - csp-reports.example.com
```

## Config params

| Parameter                   | Description                               | Default                                                 |
| --------------------------- | :-------------------------------          | :-----------------------------                          |
| `ingress`                   | A standard ingress block                  |                                                         |
| `ingress.enabled`           | Enables or Disables the ingress block     | `false`                                                 |
| `ingress.annotations`       | Ingress annotations                       | `{}`                                                    |
| `ingress.hosts`             | List of FQDN's the be browsed to          | Not Set                                                 |
| `ingress.tls.secretName`    | Name of the secret to use                 | Not Set                                                 |
| `ingress.tls.hosts`         | List of FQDN's the above secret is associated with| Not Set                                         |
| `service.type`              | Service type                              | `ClusterIP`                                             |
| `service.port`              | Service port                              | `80`                                                    |
| `service.annotations`       | Service annotations                       | `{}`                                                    |
| `custom`                    | CLI Param Options (see Below)             |                                                         |
| `custom.debug`              | Logs in debug mode                        | `false`                                                 |
| `custom.filterlist`         | Name of file within the configMaps dir for custom filters| `false` Uses list compiled into the app  |
| `custom.jsonOutput`         | Log entries as json objects, use `false` for plain text  | `true`                                   |

[1]: https://github.com/jacobbednarz/go-csp-collector/tree/master/deployments/kubernetes-helm/values.yaml
