## hlf-cert-exporter

#### Description
The service exposes **Not Before** and **Not After** values from x509 certificates stored in kubernetes secrets.  
Primary goal is tracking Hyperledger Fabric certificates. Export can be limited by labels and namespaces.  
Works both in-cluster and out-of-cluster way.

#### Build
Clone the repo and run go build. Use go version >=1.14

#### Use
```
$ ./hlf-cert-exporter -h
Usage of ./hlf-cert-exporter:
  -label string
        List of labels for filtering, comma-separated
  -listen string
        The address to listen on for HTTP requests. (default ":9090")
  -ns string
        List of namespaces to check, comma-separated

$ ./hlf-cert-exporter -label tier=hlf -ns org1,org2
```
