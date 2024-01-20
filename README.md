# PCAP
Julia PCAP parser

# Usage

>in Julia REPL

```julia
include("path/to/PCAP.jl")
file = "path/to/file.cap"
```
> dataframes:

```
ipdf = PCAP.ip_dataframe(file)
tcpdf = PCAP.tcp_dataframe(file)
udpdf = PCAP.udp_dataframe(file)
dnsdf = PCAP.dns_dataframe(file)
```
