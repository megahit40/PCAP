

""" Print IP/TCP frames `tcpdump` style """
function dump_printstring(ip::IPv4, tcp::TCP)::Nothing
	print("IP ")
	print("$(ip.srcIP[1]).$(ip.srcIP[2]).$(ip.srcIP[3]).$(ip.srcIP[4])")
	print(".", Int(tcp.srcport), " > ")
	print("$(ip.dstIP[1]).$(ip.dstIP[2]).$(ip.dstIP[3]).$(ip.dstIP[4])")
	print(".", Int(tcp.dstport))
	print(" TCP")
	print(" Flags ")
	show(tcp.flag)	
	print(" seq ", tcp.seq, 
		  " ack ", tcp.ackno,
		  " win ", tcp.win, 
		  " length ", sizeof(tcp.payload))
	return nothing
end

function dump_printstring(ip::IPv4, tcp::TCP_IPv4_raw)::Nothing
	print("IP ")
	print("$(ip.srcIP[1]).$(ip.srcIP[2]).$(ip.srcIP[3]).$(ip.srcIP[4])")
	print(" ")
	print("$(ip.dstIP[1]).$(ip.dstIP[2]).$(ip.dstIP[3]).$(ip.dstIP[4])")
	print(" ")
	for byte in tcp.payload
		print(Char(byte))
	end
	return nothing
end

""" Print IP/UDP frames `tcpdump` style """
function dump_printstring(ip::IPv4, udp::UDP)::Nothing
	print("IP ")
	print("$(ip.srcIP[1]).$(ip.srcIP[2]).$(ip.srcIP[3]).$(ip.srcIP[4])")
	print(".", Int(udp.srcport), " > ")
	print("$(ip.dstIP[1]).$(ip.dstIP[2]).$(ip.dstIP[3]).$(ip.dstIP[4])")
	print(".", Int(udp.dstport))
	print(" UDP")
	print(" len ", udp.length, 
		  " chcksum ", udp.checksum,
		  " payload size ", sizeof(udp.payload))
	if udp.dstport == 53
		dns = parse_dns(udp)
		query = parse_DNSquery(dns.qname)
		dns.qclass == 1 ? (class = "IN") : (class = dns.qclass)
		dns.qtype == 1 ? (type = "A") : (type = dns.qtype)
		dns.qtype == 16 ? (type = "AAAA") : (type = dns.qtype)
		print(" ", class, " ", type, " ", query)
	end
	return nothing
end

## TODO: Need to parse dns.qopt

""" Dump frames++ like `tcpdump` """
function dumpcap(file::String, num::Int64)::Nothing
	print("Reading from file ", file)
	header = pcap_header(file)
	if header == 1 # return 1 in pcap_header()
		return println("Quitting now.")
	else
		if header.linktype == 1
			print(", link-type IEEE 802.3 (Ethernet)")
		elseif header.linktype == 228
			print(", link-type IPv4 (Raw IPv4)")
		end
		print(", snapshot length ", header.snaplen,"\n")
	end
	# first frame begins at 0x18
	frame = _get_eth_frame(file, 0x18, header.linktype)
	print(Dates.unix2datetime(frame.epoch),".",frame.nano)
	print(" ")
	ip = ip_packet(frame)
	if ip.proto == 6
		if header.linktype == 228	
			tcp = tcp_segment_IPv4_raw(ip)
		else
			tcp = tcp_segment(ip)
		end
	dump_printstring(ip, tcp)
	elseif ip.proto == 17
		udp = udp_datagram(ip)
		dump_printstring(ip, udp)
	end
	println()
	i = 1
	for n in 2:num
		frame
		if frame.next != 0
			frame = _get_eth_frame(file, frame.next, header.linktype)
			i += 1
		else
			println("$i frames read")
			return
		end
		print(Dates.unix2datetime(frame.epoch), ".", frame.nano)
		print(" ")
		ip = ip_packet(frame)
		if ip.proto == 6 
			if header.linktype == 228	
				tcp = tcp_segment_IPv4_raw(ip)
			else
				tcp = tcp_segment(ip)
			end
			dump_printstring(ip, tcp)
		elseif ip.proto == 17
			udp = udp_datagram(ip)
			dump_printstring(ip, udp)
		end
		println()
	end
	println("$i frames read")
	return nothing
end

# TODO
# shortcut functions:

function dump_ip()
end

function dump_tcp()
end

function dump_udp()
end

function dump_dns()
end
