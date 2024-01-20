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
# Dataframe with IP info
julia> ipdf = PCAP.ip_dataframe(file)
# or n numbers of frames
julia> ipdf = PCAP.ip_dataframe(file, n)
# Dataframe with tcp etc.
julia> tcpdf = PCAP.tcp_dataframe(file)
julia> tcpdf = PCAP.tcp_dataframe(file, n)
julia> udpdf = PCAP.udp_dataframe(file)
julia> udpdf = PCAP.udp_dataframe(file, n)
julia> dnsdf = PCAP.dns_dataframe(file)
julia> dnsdf = PCAP.dns_dataframe(file, n)
```

> Pretty print

```julia
julia> frame = PCAP.capframe(file, n)
julia> PCAP.prettyprint(frame)
```

