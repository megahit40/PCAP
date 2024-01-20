
struct IPv4
	ver::UInt8
	servicefield::UInt8	#00
	len::UInt16
	id::UInt16
	flags_offset::UInt16	# 3+13 bitfield
	ttl::UInt8
	proto::UInt8			#0x06 = tcp, 0x11 = udp
	checksum::UInt16
	srcIP::UInt32
	dstIP::UInt32
	payload::Vector{UInt8}
end

""" Unpack SDU from Frame """
function parseIPv4(data::Vector{UInt8})::IPv4
	io = IOBuffer(data)
	ver = read(io, UInt8)
	# TODO: if ver != 0x45 ? "optional type"
	servicefield = read(io, UInt8)
	len = ntoh(read(io, UInt16))
	id = ntoh(read(io, UInt16))
	flags_offset = ntoh(read(io, UInt16))
	ttl = read(io, UInt8)
	proto = read(io, UInt8)
	checksum = read(io, UInt16)
	srcIP = ntoh(read(io, UInt32))
	dstIP = ntoh(read(io, UInt32))
	payload = read(io)
	return IPv4(
			ver,
			servicefield,
			len,
			id,
			flags_offset,
			ttl,
			proto,
			checksum,
			srcIP,
			dstIP,
			payload)
end


function parseIPv4addr(num::UInt32)::String
	data = _num_to_IPv4_vector(num)
	if length(data) == 4
		return "$(data[1]).$(data[2]).$(data[3]).$(data[4])"
	else
		return "Format error"
	end
end

function _IPv4_vector_to_num(data::Vector{UInt8})::UInt32
	num = UInt32(0)
    num += UInt32(data[1])<<24
    num += UInt32(data[2])<<16
    num += UInt32(data[3])<<8
    num += UInt32(data[4])
    return num
end

function _num_to_IPv4_vector(num::UInt32)::Vector{UInt8}
    ip1 = num>>24
    ip2 = num<<8>>24
    ip3 = num<<16>>24
    ip4 = num<<24>>24
    return [UInt8(ip1), UInt8(ip2), UInt8(ip3), UInt8(ip4)]
end

function num_to_IPv4addr(num::UInt32)::String
	return (parseIPv4addr ∘ _num_to_IPv4_vector)(num)
end

function IP_flags_offset(flags_offset::UInt16)
	flags::UInt8 = flags_offset >> 13
	offset::UInt16 = flags_offset << 11 >> 11
	return flags, offset
end
