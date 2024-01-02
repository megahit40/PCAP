
# Pretty printing

"""Pretty printing from frame"""
function prettyprint(frame::EthernetIIframe)::Nothing
	if frame.type == 0x0800
		println("IEEE 802.3")
	end
	ip = ip_packet(frame)
	pretty_IPv4_header(ip)
	if ip.proto == 6 #tcp
		tcp = tcp_segment(ip)
		pretty_tcp_header(tcp)
	elseif ip.proto == 17 #udp
		udp = udp_datagram(ip)
		pretty_udp_header(udp)
		if udp.dstport == 53
			dns = dns_message(udp)
			print_dns_flags(dns.flags)
			println("\nQueries:")
			println(dns.query[1].qname)
		end
	end
	return nothing

end

"""Pretty printing of IPv4 header"""
function pretty_IPv4_header(header::IPv4)::Nothing
	print("""

	             IPv4 Header
	     0         1         2       3
	+----+----+------+--+--------+--------+
	|Ver.| IHL| DSCP |ECN|	Total Length  |
	+-------------------------------------+
	|  """)
	print(header.ver>>4)
	print("    ")
	print(header.ver<<4>>4)
	print("     ")
	print(header.servicefield<<2>>2)
	print("    ")
	print(header.servicefield<<6>>6)
	print("        ")
	print(header.len)
	print("        |\n")
	print("""
	+----------------+---+----------------+
	|        Id.     |Flg|  Frag. offset  |
	+-------------------------------------+
	|         """)
	print(header.id)
	print("       ")
	print(bitstring(IP_flags_offset(header.flags_offset)[1])[6:8])
	print("   ")
	print(bitstring(IP_flags_offset(header.flags_offset)[2])[1:13])
	print("|\n")
	print("""
	+---------+---------+---------+-------+
	|    ttl  |  proto  |      checksum   |
	+-------------------------------------+
	|    """)
	print(header.ttl)
	print("   |    ")
	print(header.proto)
	print("    |      ")
	print(header.checksum)
	print("          |\n")
	print("""
	+-------------------------------------+
	|                src IP               |
	+-------------------------------------+
	|            """)
	print(parseIPv4addr(header.srcIP))
	print("            |\n")
	print("""
	+-------------------------------------+
	|                dst IP               |
	+-------------------------------------+
	|           """)
	print(parseIPv4addr(header.dstIP))
	print("           |\n")
	print("""
	+-------------------------------------+
	|               Payload               |
	+-------------------------------------+
	|              """)
	print(sizeof(header.payload), " bytes")
	print("               |\n")
	print("""
	+-------------------------------------+\n
	""")
	return nothing
end

"""Pretty print based on protocol"""
function pretty_proto_header(packet::IPv4)::Nothing
	if packet.proto == 6
		tcp = tcp_segment(packet)
		return pretty_tcp_header(tcp)
	elseif packet.proto == 17
		udp = udp_datagram(packet)
		return pretty_udp_header(udp)
	end
	return nothing
end


""" Protocol 6 """
function pretty_tcp_header(tcp::TCP)
	print("""

	             TCP Header
	 0                              15
	+----------------+----------------+
	|   Source port  |   Dst. port    |
	+---------------------------------+
	|      """)
	print(tcp.srcport)
	print("     |      ")
	print(tcp.dstport)
	print("        |\n")
	print("""
	+---------------------------------+
	|            Seq number           |	
	+---------------------------------+
	|	     """)
	print(tcp.seq)
	print("            |\n")

	print("""
	+---------------------------------+
	|           Ack. number           |	
	+---------------------------------+
	|	      """)
	print(tcp.ackno)
	println("            |")
	print("""
	+----+----+-+-+-+-+-+-+-+-+-------+
	|Data|res |C|E|U|A|P|R|S|F|       |
	|off |erv |W|C|R|C|S|S|Y|I|  Win. |
	|set |ed  |R|E|G|K|H|T|N|N|  size |	
	+---------------------------------+
	| """)
	print(tcp.len>>4) # first 4 bits
	print("  | ")
	print(tcp.len<<4>>4) # last 4 bits
	print("  |")
	print(tcp.flag>>7) # first bit
	print("|")
	print(tcp.flag<<1>>7) # second bit
	print("|")
	print(tcp.flag<<2>>7) # 3rd bit
	print("|")
	print(tcp.flag<<3>>7) # 4th bit
	print("|")
	print(tcp.flag<<4>>7) # 5th bit
	print("|")
	print(tcp.flag<<5>>7) # 6th bit
	print("|")
	print(tcp.flag<<6>>7) # 7th bit
	print("|")
	print(tcp.flag<<7>>7) # 8th bit
	print("| ")
	print(tcp.win)
	print(" |\n")
	print("""
	+---------------------------------+
	|   Checksum     |   urgent ptr.  |
	+---------------------------------+
	|	 """)
	print(tcp.checksum)
	print("       |        ")
	print(tcp.urgptr)
	print("       |\n")
	print("""
	+---------------------------------+
	|           Payload               |
	+---------------------------------+
	|	         """)
	print(sizeof(tcp.payload))
	print("                |\n")
	print("""
	+---------------------------------+\n
	""")
	return nothing
end

""" Protocol 17 """
function pretty_udp_header(udp::UDP)::Nothing
	print("""

	             UDP Header
	       0                  1
	+----------------+----------------+
	|   Source port  |   Dest. port   |
	+----------------+----------------+
	|      """)
	print(udp.srcport)
	print("     |     ")
	print(udp.dstport)
	print("         |\n")
	print("""
	+----------------+----------------+
	|    Length      |   Checksum     |
	+----------------+----------------+
	|       """)
	print(udp.length)
	print("       |        ")
	print(udp.checksum)
	print("       |\n")
	print("""
	+---------------------------------+
	|              Payload            |
	+---------------------------------+
	|               """)
	print(sizeof(udp.payload))
	println("                |")
	println("""
	+---------------------------------+
	""")
	return nothing
end


function pretty_application(dns::DNS)::Nothing

	print("""        DNS Header
	       0                  1
	+----------------+----------------+
	|               ID                |
	+----------------+----------------+
	|              """)
	print(dns.id)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             FLAGS               |
	+----------------+----------------+
	|              """)
	print(dns.flags)
	print("              |\n")
	print_dns_flags(dns.flags)
	print("""
	+----------------+----------------+
	|             QDCOUNT             |
	+----------------+----------------+
	|              """)
	print(dns.qdcount)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             ANCOUNT             |
	+----------------+----------------+
	|              """)
	print(dns.ancount)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             NSCOUNT             |
	+----------------+----------------+
	|              """)
	print(dns.nscount)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             ARCOUNT             |
	+----------------+----------------+
	|               """)
	print(dns.arcount)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             QUERY             |
	+----------------+----------------+
	|           """)
	print(dns.query[1].qname)
	print("          |\n")
	print("""
	+----------------+----------------+
	|             ANSWER             |
	+----------------+----------------+
	|               """)
	print(dns.answer)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             NSRECORD             |
	+----------------+----------------+
	|               """)
	print(dns.nsrecords)
	print("              |\n")
	print("""
	+----------------+----------------+
	|             ADRECORD             |
	+----------------+----------------+
	|    """)
	print(dns.adrecords)
	print("   |\n")
	println("""
	+---------------------------------+
	""")
	return nothing

	return nothing
end

function pretty_DNS_header(data::Vector{UInt8})::Nothing
	nothing
end
