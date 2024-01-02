
include("IPv4.jl")
include("IPv6.jl")

""" Read SDU (service data unit) from Frame """
function ip_packet(frame::Union{EthernetIIframe, Frame})
	if typeof(frame) == Frame
		return parseIPv4(frame.data)
	end
	if frame.type == 0x0800
		return parseIPv4(frame.data)
	elseif frame.type == 0x86DD
		return parseIPv6(frame.data)
	elseif frame.type == 0x0806
		return nothing # ARP 
	end
end

