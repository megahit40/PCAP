module Test

using Plots, DataFrames

include("../src/Pcap.jl")

file = "sample.cap"

## Info about capfile
#PCAP.capinfo(file)

frame_no = 44
capframe = PCAP.get_frame(file, frame_no)
ip = PCAP.ip_packet(capframe)
udp = PCAP.udp_datagram(ip)
if udp != nothing
	println("Frame, ", frame_no)
	dns = PCAP.dns_message(udp)
	if dns == nothing
		println("No dns message")
	elseif dns.query != nothing && length(dns.query) > 0
		qname = dns.query[1].qname
	else
		qname = missing
	end
	println(dns.flags," ", qname)
end

#df = PCAP.dns_dataframe(file, 1184)
#println(df)
#println(frame)
#println(ip)
#println(udp)
#println(dns)


## DataFrame
#df = PCAP.reader(file, 100)
#println(dframe)
## Group dataframes
#gdf = DataFrames.groupby(df, :srcIP)
## Combine
# DataFrames.combine(gdf, DataFrames.nrow)
## Top 5 dst IP
#top5 = sort(DataFrames.combine(gdf, DataFrames.nrow), :2, rev=true)[1:5, :]
#println(top5)


## TTL
#gdf = DataFrames.groupby(df, :ttl)
#ttl = combine(gdf, nrow)
#sort!(ttl)

#plt = bar(ttl.ttl, ttl.nrow, title="TTL, sample_net", xlabel="TTL", ylabel="Count", label=false)
#display(plt)

#UnixDateTime
#using Dates
#dt = Dates.unix2datetime(parse(Float64 ,"1669882233.401206"))
# 2022-12-01T08:10:33.401
# Dates.day(dt)
# 1
## parse.(Float64, df.date)
## Vector{Float64} of all dates from string-column in df

## Markdown
# using Latexify
# md = latexify(df, latex=false)

## Join dataframes on :Frame (common key):
#newdf = innerjoin(ip, udp, on = :Frame)

println()
end
