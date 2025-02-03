# PKPR

**PKPR (Port Keeper) is a port scanner that keeps track of your open ports.**

PKPR scans ports on given targets (IPs, hosts or IP ranges). Every discovered open port that is not on a whitelist is reported. Additionally, every closed port that is supposed to be open is reported as well.

### Usage

**Scan all ports on 1 host**

Define whitelist in [example1.yaml](fixtures/whitelist1.yaml):
```yaml
- host: turris
  tcp:
    22: SSH
    53: DNS
    80: HTTP
    4443: HTTPS
```

```
pkpr -h 192.168.0.1 -w fixtures/whitelist1.yaml

PKPR - Port monitoring in Golang v1.2

[INF] Running CONNECT scan with non root privileges
turris:22
turris:853
turris:53
turris:80
turris:443
[INF] Progress: 100 % (65535/65535 packets)
[INF] Found 5 ports on host turris (192.168.0.1)
[ERR] Port TCP/853 on turris (192.168.0.1) is OPEN, but should be closed!
[ERR] Port TCP/443 on turris (192.168.0.1) is OPEN, but should be closed!
[WRN] Port TCP/4443 (HTTPS) on turris (192.168.0.1) is CLOSED, but should be open!
```

**Fast scan (Nmap top 100 ports) CIDR with JSON output**

```
pkpr -h 192.168.0.1/24 -tp 100 -w fixtures/whitelist1.yaml -o alerts.json

PKPR - Port monitoring in Golang v1.2

[INF] Running CONNECT scan with non root privileges
[INF] Progress:   6 % (1530/25600 packets)
[INF] Progress:  12 % (3037/25600 packets)
[INF] Progress:  18 % (4537/25600 packets)
192.168.0.1:80
[INF] Progress:  24 % (6040/25600 packets)
192.168.0.1:53
[INF] Progress:  30 % (7556/25600 packets)
[INF] Progress:  35 % (9047/25600 packets)
[INF] Progress:  41 % (10536/25600 packets)
[INF] Progress:  47 % (12059/25600 packets)
[INF] Progress:  53 % (13539/25600 packets)
[INF] Progress:  59 % (15033/25600 packets)
[INF] Progress:  65 % (16539/25600 packets)
192.168.0.1:22
[INF] Progress:  71 % (18065/25600 packets)
192.168.0.118:8888
[INF] Progress:  76 % (19545/25600 packets)
[INF] Progress:  82 % (21046/25600 packets)
[INF] Progress:  88 % (22555/25600 packets)
[INF] Progress:  94 % (24051/25600 packets)
192.168.0.1:443
[INF] Progress: 100 % (25548/25600 packets)
[INF] Progress: 100 % (25600/25600 packets)
[INF] Found 4 ports on host 192.168.0.1 (192.168.0.1)
[ERR] Port TCP/443 on 192.168.0.1 (turris) is OPEN but should be closed!
[WRN] Port TCP/4443 (HTTPS) on 192.168.0.1 (turris) is CLOSED but should be open!
[INF] Found 1 ports on host 192.168.0.118 (192.168.0.118)
[ERR] Port TCP/8888 on 192.168.0.118 (amaterasu) is OPEN but should be closed!
[INF] Results written to "alerts.json".
```

Content of `alerts.json`:
```json
[
  {
    "host": "turris",
    "ip": "192.168.0.1",
    "port": {
      "Port": 443,
      "Label": "",
      "Protocol": "tcp"
    },
    "open": true,
    "severity": "ERR"
  },
  {
    "host": "turris",
    "ip": "192.168.0.1",
    "port": {
      "Port": 4443,
      "Label": "HTTPS",
      "Protocol": "tcp"
    },
    "open": false,
    "severity": "WARN"
  },
  {
    "host": "amaterasu",
    "ip": "192.168.0.118",
    "port": {
      "Port": 8888,
      "Label": "",
      "Protocol": "tcp"
    },
    "open": true,
    "severity": "ERR"
  }
]
```

### Build

**Requirements**

- Go v1.22+
- Libpcap

```
make build
```

### Whitelist format

List of whitelisted hosts and their known ports:

```yaml
- host: <domain1|ip1>[, <domain2|ip2> ...]
  tcp:
    <port1>: <description1>
    <port2>: <description2>
  udp:
    <port3>: <description3>
```

---

- PKPR has embedded lovely [Naabu](https://github.com/projectdiscovery/naabu) port scanner in its core.
