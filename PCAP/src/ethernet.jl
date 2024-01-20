
# Raw IPv4 frame
struct Frame
	start::Int64	
	epoch::UInt32
	nano::UInt32		# or micro ...
	inclen::UInt32
	origlen::UInt32
	data::Vector{UInt8}
	next::Int64
end

# EthernetII frame:
struct EthernetIIframe
	start::Int64	
	epoch::UInt32
	nano::UInt32		# or micro ...
	inclen::UInt32
	origlen::UInt32
	srcmac::Vector{UInt8}
	dstmac::Vector{UInt8}
	type::UInt16
	data::Vector{UInt8}
	next::Int64
end

""" Frame selector based on pcap linktype """
function _get_eth_frame(filename::String, pos, linktype::UInt32)
	if linktype == 1
		return eth_frame_II(filename, pos)
	end
	if linktype == 228
		return eth_frame_IPv4_raw(filename, pos)
	end
end

""" Frame selector based on pcap linktype """
function _get_eth_frame(io::IOStream, linktype::UInt32)::Union{EthernetIIframe, Frame}
	if linktype == 1
		return eth_frame_II(io)
	end
	if linktype == 228
		return eth_frame_IPv4_raw(io)
	end
end


""" Return EthernetIIFrame object"""
function eth_frame_II(io::IOStream)::EthernetIIframe
	pos = position(io)
	epoch = read(io, UInt32)
	nano = read(io, UInt32) 	# or micro ...
	inclen = read(io, UInt32)
	origlen = read(io, UInt32)
	dstmac = read(io, 6) 		# see parseMAC()
	srcmac = read(io, 6)
	type = ntoh(read(io, UInt16))
	data = read(io, inclen-14) 	# - type, dst, src
	next = position(io)
	if eof(io) == true
		next = 0
	end
	return EthernetIIframe(
			pos,
			epoch,
			nano,
			inclen,
			origlen,
			srcmac,
			dstmac,
			type,
			data,
			next)
end



""" Return EthernetIIFrame object"""
function eth_frame_II(filename::String, pos)::EthernetIIframe
	io = open(filename)
	seek(io, pos)
	epoch = read(io, UInt32)
	nano = read(io, UInt32) # or micro ...
	inclen = read(io, UInt32)
	origlen = read(io, UInt32)
	dstmac = read(io, 6) # see parseMAC()
	srcmac = read(io, 6)
	type = ntoh(read(io, UInt16))
	data = read(io, inclen-14) # Correct (- type, dst, src)
	next = position(io)
	if eof(io) == true
		next = 0
	end
	close(io)
	return EthernetIIframe(
			pos,
			epoch,
			nano,
			inclen,
			origlen,
			srcmac,
			dstmac,
			type,
			data,
			next)
end


""" Return type 228 Frame object """
function eth_frame_IPv4_raw(filename::String, pos)::Frame
	io = open(filename)
	seek(io, pos)
	epoch = read(io, UInt32)
	nano = read(io, UInt32)
	inclen = read(io, UInt32)
	origlen = read(io, UInt32)
	data = read(io, inclen)
	next = position(io)
	if eof(io) == true
		next = 0
	end
	close(io)
	return Frame(
			pos,
			epoch,
			nano,
			inclen,
			origlen,
			data,
			next)
end

""" Return type 228 Frame object """
function eth_frame_IPv4_raw(io::IOStream)::Frame
	pos = position(io)
	epoch = read(io, UInt32)
	nano = read(io, UInt32)
	inclen = read(io, UInt32)
	origlen = read(io, UInt32)
	data = read(io, inclen)
	next = position(io)
	if eof(io) == true
		next = 0
	end
	return Frame(
			pos,
			epoch,
			nano,
			inclen,
			origlen,
			data,
			next)
end


""" 
Shortcut to get ether type directly,
without parsing full header
much much much faster
"""
function get_ether_type(frame_data::Vector{UInt8})
	io = IOBuffer(frame_data)
	skip(io, 12) # srcmac(6) + dstmac(6)
	type = ntoh(read(io, UInt16))
	return type
end

""" parse MAC address from vector """
function parseMAC(data::Vector{UInt8})
	mac = ""
	for i in 1:6
		mac *= bytes2hex(data[i])
		if i < 6
			mac *= ":"
		end
	end
	return mac
end

## TODO: Fix trailing padding ... Lengths of frames and protocols does not match.
## See Pcap.jl (same comment, don't know where to implement fix ...)
## Will probably propagate to applicatoin level. E.g. dns ...
