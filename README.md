# bdd-acl

A firewall that captures live network traffic using eBPF and checks each packet against an ACL encoded as a Binary Decision Diagram (BDD).

## How it works

```
Network traffic
      │
      ▼
 eBPF / pcap          ← captures packets at the kernel level
      │
      ▼
  ACL Engine          ← encodes rules as a BDD for fast set-based matching
      │
      ▼
 ACCEPT / DENY        ← logged to the console with color
```

Each rule in `policy.txt` is compiled into a BDD node. Incoming packets are checked against the combined policy BDD — green for ACCEPT, red for DENY.

## Policy format

```
Action;Protocol;sport=<port>;sip=<ip>;dport=<port>;dip=<ip>
```

- Action: `Accept` or `Denial`
- Protocol: `TCP` or `UDP`
- Use `*` for wildcard ports or IP octets (e.g. `192.168.1.*`)

## Run

```bash
sudo ./bdd-acl          # default: en0
sudo ./bdd-acl en1      # specify interface
```

Requires root to open the pcap handle.

<img width="916" height="386" alt="image" src="https://github.com/user-attachments/assets/c4793393-147b-4fa3-8b33-c93a3a9e5466" />

For more details on how it works please check the blog post [here](https://msf37.medium.com/how-boolean-logic-can-be-used-to-build-firewall-acls-c98e80cc8d00).
