
struct IPv4
	ver::UInt8
	servicefield::UInt8	#00
	len::Int16
	id::UInt16
	flags_offset::UInt16	# 3+13 bitfield
	ttl::UInt8
	proto::UInt8	#0x06 = tcp, 0x11 = udp
	checksum::UInt16
	srcIP::Vector{UInt8}
	dstIP::Vector{UInt8}
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
	srcIP = read(io, 4)
	dstIP = read(io, 4)
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


function parseIPv4addr(data::Vector{UInt8})
	if length(data) == 4
		return "$(data[1]).$(data[2]).$(data[3]).$(data[4])"
	else
		return "Format error"
	end
end

function IP_flags_offset(flags_offset::UInt16)
	flags::UInt8 = flags_offset >> 13
	offset::UInt16 = flags_offset << 11 >> 11
	return flags, offset
end
