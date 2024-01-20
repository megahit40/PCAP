# PCAP
Julia PCAP parser

# Usage

```julia
julia> include("path/to/PCAP.jl")

```
> CAP-file info

```julia
julia> file = "path/to/capfile.cap"
julia> PCAP.capinfo(file)
```

> dataframes:

```julia
julia> file = "path/to/file.cap"
julia> ipdf = PCAP.ip_dataframe(file)
julia> tcpdf = PCAP.tcp_dataframe(file)
julia> udpdf = PCAP.udp_dataframe(file)
julia> dnsdf = PCAP.dns_dataframe(file)
```
