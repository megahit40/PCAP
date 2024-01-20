
struct TCP
	srcport::UInt16
	dstport::UInt16
	seq::UInt32
	ackno::UInt32
	# len + flag is UInt16 bitstring
	len::UInt8 		# bitstring ...
	flag::UInt8 		# bitstring ...
	win::UInt16 
	checksum::UInt16
	urgptr::UInt16
	payload::Vector{UInt8}
end


struct TCP_IPv4_raw
	payload::Vector{UInt8}
end

function tcp_segment_IPv4_raw(packet::IPv4)
	io = IOBuffer(packet.payload)
	payload = read(io)
	close(io)
	return TCP_IPv4_raw(
			payload)
end

## On a pure listening device the 'payload'
## can be three things:
## 1. option field because data can not be sent 
## before a 3-way handshake is completed.
## or 
## 2. Padding or 'trailer'. Should be zeroes. If not,
## "non-zero" padding exists.
## or
## 3. Options AND padding ?

function tcp_segment(packet::IPv4)
	if packet.proto != 6
		return nothing
	end
	return _parse_tcp_segment(packet.payload)
end

function _parse_tcp_segment(payload::Vector{UInt8})::TCP
	io = IOBuffer(payload)
	srcport = ntoh(read(io, UInt16))
	dstport = ntoh(read(io, UInt16))
	seq = read(io, UInt32)
	ackno = read(io, UInt32)
	len = read(io, UInt8)
	flag = read(io, UInt8)
	win = ntoh(read(io, UInt16))
	checksum = read(io, UInt16)
	urgptr = read(io, UInt16)
	# Pure listening: 'payload' is either options or padding or both?
	payload = read(io)
	close(io)
	return TCP(
			srcport,
			dstport,
			seq,
			ackno,
			len,
			flag,
			win,
			checksum,
			urgptr,
			payload)
end



"""Returns tcp flags from 16-bit number"""
function print_tcp_flags(flag::UInt8)
	print("""
	+-+-+-+-+-+-+-+-+
	|C|E|U|A|P|R|S|F|
	|W|C|R|C|S|S|Y|I|
	|R|E|G|K|H|T|N|N|	
	+---------------+
	 """)
	print(flag>>7) # first bit
	print("|")
	print(flag<<1>>7) # second bit
	print("|")
	print(flag<<2>>7) # 3rd bit
	print("|")
	print(flag<<3>>7) # 4th bit
	print("|")
	print(flag<<4>>7) # 5th bit
	print("|")
	print(flag<<5>>7) # 6th bit
	print("|")
	print(flag<<6>>7) # 7th bit
	print("|")
	print(flag<<7>>7) # 8th bit
	println()
end
