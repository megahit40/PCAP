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
include("dataframes.jl")

""" Libpcap file header, 24 octets (bytes pos. 0x00-0x18) """
struct Header
	magicnumber::UInt32		# A1B2C3D4 (micros) or A1B23C4D (nanos)
	majorver::UInt16		# 2
	minver::UInt16			# 4
	res1::UInt32			# Should be 0.
	res2::UInt32			# Should be 0.
	snaplen::UInt32			# max octets captured
	linktype::UInt32		# 1 = IEEE 802.3 Ethernet
end

""" Return 'header' type """
function pcap_header(filename::String)::Union{Header, Int64}
	# Header 0x00-0x18 (24 octets)
	io = open(filename, "r")
	magicnum = read(io, UInt32)
	if magicnum != 0xA1B2C3D4 && magicnum != 0xA1B23C4D
		println("\nInvalid file format!")
		close(io)
		return 1
	end
	majv = read(io, UInt16)		
	minv = read(io, UInt16)		
	res1 = read(io, UInt32)		
	res2 = read(io, UInt32)		
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
function _pcap_header(io::IOStream)::Header
	# Header 0x00-0x18 (24 octets)
	magicnum = read(io, UInt32)
	if magicnum != 0xA1B2C3D4 && magicnum != 0xA1B23C4D
		println("\nInvalid file format!")
		return 1
	end
	majv = read(io, UInt16)		
	minv = read(io, UInt16)		
	res1 = read(io, UInt32)		
	res2 = read(io, UInt32)		
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
function _count_frames(file::String)::Int64
	io = open(file)
	seek(io, 0x18+4+4) 	# epoch + micros/nanos
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
function capinfo(file::String)::Nothing
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
	no_frames = _count_frames(file)
	println("Frame count: ", no_frames)
	frame = capframe(file, 1)
	println("First frame: ", Dates.unix2datetime(frame.epoch))
	frame = capframe(file, no_frames)
	println("Last frame: ", Dates.unix2datetime(frame.epoch))
	#return no_frames, header
	return nothing
end


"""Get frame by number"""
function capframe(file::String, num::Int64)::Union{EthernetIIframe, Frame}
	io = open(file)
	header = _pcap_header(io)
	next = 0x18		# first frame
	for n in 2:num
		seek(io, next + 8)
		inclen = read(io, UInt32)
		skip(io, 4+inclen)
		next = position(io)
		if eof(io)
			break
		end
	end
	close(io)
	return _get_eth_frame(file, next, UInt32(header.linktype))
end


### Composed wrapper functions

""" 
Wrapper function
Will error if frame does not contain IPv4.
"""
function get_ip_packet(file::String, frame::Int64)::Union{IPv4, Nothing}
	return (ip_packet ∘ capframe)(file, frame)
end

""" 
Wrapper composition function
Will error if frame does not contain TCP.
"""
function get_tcp_segment(file::String, frame::Int64)::Union{TCP, Nothing}
	return (tcp_segment ∘ ip_packet ∘ capframe)(file, frame)
end


""" 
Wrapper function.

	get_udp_datagram(file::String, frame::Int) -> UDP
	
Will error if frame does not contain UDP.
"""
function get_udp_datagram(file::String, frame::Int64)::Union{UDP, Nothing}
	return (udp_datagram ∘ ip_packet ∘ capframe)(file, frame)
end

""" 
Wrapper composition function.
Will error if frame does not contain UDP+DNS.
"""
function get_dns_message(file::String, frame::Int64)::Union{DNS, Nothing}
	udp = get_udp_datagram(file, frame)
	
	if udp == nothing 
		return nothing
	end

	return dns_message(udp)
end

"""
Wrapper function.
Will error if frame does not contain DNS query. 
"""
function get_dns_qname(file, frame)::String
	dns = get_dns_message(file, frame)
	return dns.query[1].qname
end

# Unused

"""Returns next frame position"""
function frame_next_pos(filename::String, pos)::Int64
	io = open(filename)
	seek(io, pos+4+4) #epoch, micro/nano
	inclen = read(io, UInt32)
	skip(io, 4+inclen)
	next = position(io)
	close(io)
	return next
end


end # module
