module PCAP

using Dates
using DataFrames

include("ethernet.jl")
include("ip.jl")
include("tcp.jl")
include("udp.jl")
include("dns.jl")
include("pretty_print.jl")
include("dumpcap.jl")

struct Header
	# Header 0x00-0x18: 24 octets
	magicnumber::UInt32	# A1B2C3D4 (micros) or A1B23C4D (nanos)
	majorver::UInt16	# 2
	minver::UInt16		# 4
	res1::UInt32		# Should be 0.
	res2::UInt32		# Should be 0.
	snaplen::UInt32		# max octets captured
	linktype::UInt32	# 1 = IEEE 802.3 Ethernet
end

""" Return 'header' type """
function pcap_header(filename::String)::Union{Header, Int}
	# Header 0x00-0x18 (24 octets)
	io = open(filename, "r")
	magicnum = read(io, UInt32)
	if magicnum != 0xA1B2C3D4
		if magicnum != 0xA1B23C4D
			println("\nInvalid file format!")
			close(io)
			return 1
		end
	end
	majv = read(io, UInt16)		
	minv = read(io, UInt16)		
	res1 = read(io, Int32)		
	res2 = read(io, Int32)		
	snaplen = read(io, UInt32)	
	linktype = read(io, UInt32) 
	close(io)
	# Create header struct
	return Header(
			magicnum,
			majv,
			minv,
			res1,
			res2,
			snaplen,
			linktype)
end

""" Return 'header' type """
function pcap_header(io::IOStream)::Header
	# Header 0x00-0x18 (24 octets)
	magicnum = read(io, UInt32)
	if magicnum != 0xA1B2C3D4
		if magicnum != 0xA1B23C4D
			println("\nInvalid file format!")
			return 1
		end
	end
	majv = read(io, UInt16)		
	minv = read(io, UInt16)		
	res1 = read(io, Int32)		
	res2 = read(io, Int32)		
	snaplen = read(io, UInt32)	
	linktype = read(io, UInt32) 
	# Create header struct
	return Header(
			magicnum,
			majv,
			minv,
			res1,
			res2,
			snaplen,
			linktype)
end

""" Count frames """
function count_frames(file::String)::Int
	io = open(file)
	seek(io, 0x18+4+4) #epoch,nano
	inclen = read(io, UInt32)
	skip(io, 4+inclen)
	next = position(io)
	n = 1
	while !eof(io)
		seek(io, next+4+4)
		inclen = read(io, UInt32)
		skip(io, 4+inclen)
		next = position(io)
		n += 1
	end
	close(io)
	return n
end

""" Return info about capfile """
function capinfo(file::String)
	header = pcap_header(file)
	if header == 1
		println("Not valid magicnumber")
		return (nothing, nothing)
	end
	print("Magicnumber: ")
	show(header.magicnumber)
	if header.magicnumber == 0xA1B2C3D4
		print(" (microseconds)\n")
	elseif header.magicnumber == 0xA1B23C4D
		print(" (nanoseconds)\n")
	end
	println("Snaplength: ", header.snaplen)
	print("Linktype: ", header.linktype)
	if header.linktype == 1
		println(" IEEE 802.3 (Ethernet)")
	elseif header.linktype == 228
		println("IPv4 (Raw IPv4)")
	end
	no_frames = count_frames(file)
	println("Frame count: ", no_frames)
	frame = get_frame(file, 1)
	println("First frame: ", Dates.unix2datetime(frame.epoch))
	frame = get_frame(file, no_frames)
	println("Last frame: ", Dates.unix2datetime(frame.epoch))
	#return no_frames, header
	return nothing
end


"""Get frame by number"""
function get_frame(file::String, num)::Union{EthernetIIframe, Frame}
	io = open(file)
	header = pcap_header(io)
	next = 0x18
	n = 1
	for n in 2:num
		seek(io, next + 8)
		inclen = read(io, UInt32)
		skip(io, 4+inclen)
		next = position(io)
		if eof(io)
			break
		end
		n += 1
	end
	close(io)
	return _get_eth_frame(file, next, UInt32(header.linktype))
end

# Unused
"""Returns next frame position"""
function frame_next_pos(filename::String, pos)::Int
	io = open(filename)
	seek(io, pos+4+4) #epoch, micro/nano
	inclen = read(io, UInt32)
	skip(io, 4+inclen)
	next = position(io)
	close(io)
	return next
end


function _ipdf(frame, no::Int)::DataFrame
	ip = ip_packet(frame)
	return DataFrame(
		Frame = no,
		epoch = frame.epoch,
		micro = frame.nano, 
		srcIP = parseIPv4addr(ip.srcIP), 
		dstIP = parseIPv4addr(ip.dstIP),
		proto = ip.proto,
		ttl = ip.ttl)
end

function _tcpdf(ip::IPv4, no::Int)::DataFrame
	tcp = tcp_segment(ip)
	return DataFrame(
		Frame = no,
		srcport = tcp.srcport,
		dstport = tcp.dstport,
		flags = tcp.flag)
end

function _udpdf(ip::IPv4, no::Int)::DataFrame
	udp = udp_datagram(ip)
	return DataFrame(
		Frame = no,
		srcport = udp.srcport,
		dstport = udp.dstport)
end


function _dnsdf(ip::IPv4, no::Int)::DataFrame
	dns = dns_message(udp_datagram(ip))
	if dns.qdcount > 0 && dns.query != nothing && length(dns.query) != 0
		for query in dns.query
			qname = query.qname
			qclass = query.qclass
			qtype = query.qtype
			break
		end
	else
		qname = ""
		qtype = 0
		qclass = 0
	end
	df = DataFrame(
		Frame = no,
		flags = dns.flags,
		qdcount = dns.qdcount,
		ancount = dns.ancount,
		nscount = dns.nscount,
		arcount = dns.arcount,
		qname = qname,
		qtype = qtype,
		qclass = qclass)
	return df
end


function ip_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	df = _ipdf(frame, 1)
	for i in 2:no_frames
		frame = _get_eth_frame(io, header.linktype)
		df_app = _ipdf(frame, i)
		append!(df, df_app)
		if eof(io)
			break
		end
	end
	close(io)
	return df
end


function tcp_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	while ip.proto != 6
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	df = _tcpdf(ip, n)
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 6
			df_app = _tcpdf(ip, i)
			append!(df, df_app)
		end
		if eof(io)
			break
		end
	end
	close(io)
	return df
end

function udp_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	while ip.proto != 17
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	df = _udpdf(ip, n)
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 17
			df_app = _udpdf(ip, i)
			append!(df, df_app)
		end
		if eof(io)
			break
		end
	end
	close(io)
	return df
end

function dns_dataframe(file::String, no_frames::Int)
	io = open(file)
	header = pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	while ip.proto != 17 
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	ip = ip_packet(frame)
	df = _dnsdf(ip, n)
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 17
			df_app = _dnsdf(ip, i)
			append!(df, df_app)
		end
		if eof(io)
			break
		end
	end
	close(io)
	return df
end

end # module