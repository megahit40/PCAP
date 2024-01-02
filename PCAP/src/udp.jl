
struct UDP
	srcport::UInt16
	dstport::UInt16
	length::UInt16
	checksum::UInt16
	payload::Vector{UInt8}
end


function udp_datagram(packet::IPv4)
	if packet.proto != 0x11
		return nothing
	end
	return _parse_udp_datagram(packet.payload)
end

""" Return UDP datagram """
function _parse_udp_datagram(payload::Vector{UInt8})::UDP
	io = IOBuffer(payload)
	srcport = ntoh(read(io, UInt16))	
	dstport = ntoh(read(io, UInt16))
	length = ntoh(read(io, UInt16))
	checksum = ntoh(read(io, UInt16))
	payload = read(io)
	close(io)
	return UDP(
		srcport,
		dstport,
		length,
		checksum,
		payload)
end
