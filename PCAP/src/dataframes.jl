# Create dataframes

function ip_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	df = DataFrame(
		frame = 1,
		epoch = frame.epoch,
		micro = frame.nano, 
		srcIP = parseIPv4addr(ip.srcIP), 
		dstIP = parseIPv4addr(ip.dstIP),
		proto = ip.proto,
		ttl = ip.ttl)
	for i in 2:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		push!(df, (
			i, 
			frame.epoch,
			frame.nano, 
			parseIPv4addr(ip.srcIP), 
			parseIPv4addr(ip.dstIP),
			ip.proto,
			ip.ttl)
		)
		if eof(io)
			break
		end
	end
	close(io)
	return df
end


function ip_dataframe(file::String)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	df = DataFrame(
		frame = 1,
		epoch = frame.epoch,
		micro = frame.nano,
		srcIP = parseIPv4addr(ip.srcIP), 
		dstIP = parseIPv4addr(ip.dstIP),
		proto = ip.proto,
		ttl = ip.ttl)
	i = 2
	while !eof(io)
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		push!(df, (
			i, 
			frame.epoch,
			frame.nano,
			parseIPv4addr(ip.srcIP), 
			parseIPv4addr(ip.dstIP),
			ip.proto,
			ip.ttl)
		)
		i += 1
	end
	close(io)
	return df
end


function ip_dataframe_numeric_ip(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	df = DataFrame(
		frame = 1,
		epoch = frame.epoch,
		micro = frame.nano, 
		srcIP = ip.srcIP,
		dstIP = ip.dstIP,
		proto = ip.proto,
		ttl = ip.ttl)
	for i in 2:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		push!(df, (
			i, 
			frame.epoch,
			frame.nano, 
			ip.srcIP,
			ip.dstIP,
			ip.proto,
			ip.ttl)
		)
		if eof(io)
			break
		end
	end
	close(io)
	return df
end


function ip_dataframe_numeric_ip(file::String)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	df = DataFrame(
		frame = 1,
		epoch = frame.epoch,
		micro = frame.nano,
		srcIP = ip.srcIP,
		dstIP = ip.dstIP,
		proto = ip.proto,
		ttl = ip.ttl)
	i = 2
	while !eof(io)
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		push!(df, (
			i, 
			frame.epoch,
			frame.nano,
			ip.srcIP,
			ip.dstIP,
			ip.proto,
			ip.ttl)
		)
		i += 1
	end
	close(io)
	return df
end


function tcp_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	while ip.proto != 6
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	tcp = tcp_segment(ip)
	df = DataFrame(
		frame = n,
		srcport = tcp.srcport,
		dstport = tcp.dstport,
		flags = tcp.flag)
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 6
			tcp = tcp_segment(ip)
			push!(df, (
				i,
				tcp.srcport,
				tcp.dstport,
				tcp.flag)
			)
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
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	while ip.proto != 17
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	udp = udp_datagram(ip)
	df = DataFrame(
		frame = n,
		srcport = udp.srcport,
		dstport = udp.dstport)
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 17
			udp = udp_datagram(ip)
			push!(df, (i, udp.srcport, udp.dstport))
		end
		if eof(io)
			break
		end
	end
	close(io)
	return df
end


function _dns_qname_qtype_qclass(dns_query::Union{Vector{DNS_query}, Nothing}, qdcount::UInt16)::Tuple
	if dns_query == nothing
		return "", 0, 0
	end
	if length(dns_query) == 0
		return "", 0, 0
	end
	# Use only first query ...
	if qdcount > 0
		return dns_query[1].qname, dns_query[1].qtype, dns_query[1].qclass
	end		
end


function dns_dataframe(file::String, no_frames::Int)::DataFrame
	io = open(file)
	header = _pcap_header(io)
	frame = _get_eth_frame(io, header.linktype)
	ip = ip_packet(frame)
	n = 1
	
	while ip.proto != 17 
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		n += 1
	end
	
	dns = (dns_message ∘ udp_datagram)(ip)
	qname, qtype, qclass = _dns_qname_qtype_qclass(dns.query, dns.qdcount)

	df = DataFrame(
		frame = n,
		flags = dns.flags,
		qdcount = dns.qdcount,
		ancount = dns.ancount,
		nscount = dns.nscount,
		arcount = dns.arcount,
		qname = qname,
		qtype = qtype,
		qclass = qclass)
	
	n += 1
	for i in n:no_frames
		frame = _get_eth_frame(io, header.linktype)
		ip = ip_packet(frame)
		if ip.proto == 17
			dns = (dns_message ∘ udp_datagram)(ip)
			qname, qtype, qclass = _dns_qname_qtype_qclass(dns.query, dns.qdcount)
			push!(df, (
				i,
				dns.flags,
				dns.qdcount,
				dns.ancount,
				dns.nscount,
				dns.arcount,
				qname,
				qtype,
				qclass)
			)
		end
		
		if eof(io)
			break
		end
	
	end
	close(io)
	return df
end
