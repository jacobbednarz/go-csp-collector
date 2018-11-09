# Kubernetes / Helm Deployment Template for the CSP Report Collector

## TL;DR;

```console
$ helm install -n csp-reporter -f custom-values.yaml kubernetes
```

## Introduction
This chart deploys a Content Security Policy report collector from
https://github.com/jacobbednarz/go-csp-collector/

Using the [kubernetes/values.yaml][1] file create a custom-values.yaml override
with just the changed values then run the command above.
eg.
```
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
| `custom.filterlist`         | Name of file within the configMaps dir for custom filters| `false` Uses list compiled into the app  |
| `custom.jsonOutput`         | Log entries as json objects, use `false` for plain text  | `true`                                   |
| `custom.debug`              | Logs in debug mode                        | `false`                                                 |


[1]: https://github.com/jacobbednarz/go-csp-collector/kubernetes/values.yaml
