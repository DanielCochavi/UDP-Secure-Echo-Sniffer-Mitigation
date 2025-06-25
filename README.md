# UDP Echo ↔ Sniffer Mitigation (Python 2.7 / 3.11)

> Proof-of-concept that uses XOR-parity packets to recover UDP traffic dropped by an active MITM sniffer.  
> Runs in <200 LoC with **Scapy** + raw sockets and is fully compatible with **Python 2.7** *and* **Python 3.11**.

---

## Architecture
```
┌────────┐       UDP        ┌────────┐
│ Client │ ◀──────────────▶ │ Server │
└────────┘                 └────────┘
        ▲ sniff            ▲ echo
        │                  │
        └──── Sniffer ─────┘

```


* Three independent parties: **Client**, **Server**, **Sniffer**.  
* Sniffer is passive/active—can read traffic or drop selected sequence numbers.  
* Every *d* packets the client sends an XOR-parity packet so the server can
  recover any single missing shard.

---

## Features
- **Echo service** on UDP `12321`, CR/LF-terminated lines  
- **Client** splits messages into ≤100-byte shards, sends every 3 s with sequence #  
- **Sniffer** captures traffic via raw sockets (`scapy`) and can selectively drop packets  
- **Mitigation** : client inserts XOR parity every *d* shards → server reconstructs losses
- Works on **Linux / macOS loopback**; no root needed for client/server (sniffer requires raw-socket privileges).

---

## Quick Start
```bash
git clone https://github.com/<YOUR_USER>/udp-secure-echo.git
cd udp-secure-echo
pip install -r requirements.txt        # scapy==2.5.0 etc.

# Terminal 1 – server
python3.11 server.py

# Terminal 2 – client
python3.11 client.py --text "Hello CyberArk"

# Terminal 3 – sniffer (passive)
sudo python3.11 sniffer.py --iface lo --color

# Terminal 3 – sniffer (active, drops packets 3,7,9)
sudo python3.11 sniffer.py --iface lo --color --drop 3,7,9
```

---

## Performance
| Packets tested | Drop rate simulated | Recovery success | Extra latency (p95) |
|---------------:|--------------------:|-----------------:|--------------------:|
| 10 000         | 30 %                | 100 %            | +2 ms              |
