
struct DNS_header
	id::UInt16
	flags::UInt16
	qdcount::UInt16
	ancount::UInt16
	nscount::UInt16
	arcount::UInt16
end

struct DNS_query
	qname::Union{String, Nothing}
	qtype::Union{UInt16, Nothing}
	qclass::Union{UInt16, Nothing}
end

struct DNS_answer
	aname::Union{String,Nothing}
	atype::Union{UInt16, Nothing}
	aclass::Union{UInt16, Nothing}
end

struct DNS_nsrecord
	nsname::Union{String, Nothing}
	nstype::Union{UInt16, Nothing}
	nsclass::Union{UInt16, Nothing}
	ttl::Union{UInt32, Nothing}
	datalength::Union{UInt16, Nothing}
	address::Union{Vector{UInt8}, Nothing}
end

# rfc6891
struct DNS_adrecord
	arname::Union{Vector{UInt8}, Nothing} 	# must be 0 (root domain)
	artype::Union{UInt16, Nothing}		# OPT(41)
	payload_size::Union{UInt16, Nothing}	# udp payload size
	rcode::UInt8				# extended rcode
	edns0::UInt8				# .. and flags
	z::Union{UInt16, Nothing}		# .. and flags
	data_length::Union{UInt16, Nothing}	#
	data::Union{Vector{UInt8}, Nothing}	# {attribute, value} pairs
end

# Add. record data 'Vector{UInt8}':
struct DNS_options
	option_code::UInt16    # 10 = COOKIE
	option_length::UInt16
	option_data::String
end

struct DNS_flags
	qr::UInt8		# 1 bit: 0 == query, 1 = response
	opcode::UInt8		# 4 bits: type of message
	aa::UInt8		# 1 bit: authoratative answer
	tc::UInt8		# 1 bit: truncated
	rd::UInt8		# 1 bit: recursion desired
	ra::UInt8		# 1 bit: recursion avail.
	z::UInt8		# 1 bit: reserved
	ad::UInt8		# 1 bit: authentic data
	cd::UInt8		# 1 bit: checking disabled
	rcode::UInt8		# 4 bits: response info
end


struct DNS
	id::UInt16
	flags::UInt16		# |QR(1)|Opcode(4)|AA(1)|UInt16C|RD|RA|Z|AD|CD|RCODE(4)|
	qdcount::UInt16		# No. of queries
	ancount::UInt16		# No. of answers
	nscount::UInt16		# No. of nameservers (authoritative)
	arcount::UInt16		# No. of additional records
	# Records
	query::Union{Vector{DNS_query}, Nothing}
	answer::Union{Vector{DNS_answer}, Nothing}
	nsrecords::Union{Vector{DNS_nsrecord}, Nothing}
	adrecords::Union{Vector{DNS_adrecord}, Nothing}
end


""" Accept udp datagram """
function dns_message(datagram::UDP)::Union{DNS, Nothing}
	if datagram.dstport != 53 && datagram.srcport != 53
		return nothing
	end
	len = datagram.length - 8
	return _parse_dns_message(datagram.payload, len)
end

function _parse_dns_message(payload::Vector{UInt8}, len::Int64)::DNS
	io = IOBuffer(payload)
	header = _parse_dns_header(io)
	query_records, answer_records, ns_records, add_records = _parse_dns_sections(io, header, len)
	close(io)
	return DNS(
			header.id, 
			header.flags, 
			header.qdcount, 
			header.ancount, 
			header.nscount, 
			header.arcount, 
			query_records, 
			answer_records, 
			ns_records, 
			add_records)
end

function _parse_dns_header(io::IOBuffer)::DNS_header
	id = ntoh(read(io, UInt16))
	# Some flags are incorrect, check here?
	# e.g. flags >= 0x8000 = response
	flags = ntoh(read(io, UInt16))
	qdcount = ntoh(read(io, UInt16))
	ancount = ntoh(read(io, UInt16))
	nscount = ntoh(read(io, UInt16))
	arcount = ntoh(read(io, UInt16))
	return DNS_header(id, flags, qdcount, ancount, nscount, arcount)
end


function _parse_dns_sections(io::IOBuffer, header::DNS_header, len::Int)::Tuple
	# early return for excessive queries
	# sign of malformatted message
	if header.qdcount > 30 || header.flags == 0x1000
		return nothing, nothing, nothing, nothing
	end
	
	if header.flags < 0x8000 && header.arcount == 0
		return _parse_dns_query_record(io, header.qdcount, len), 
				nothing, nothing, nothing
	end
	
	if header.flags < 0x8000
		return _parse_dns_query_record(io, header.qdcount, len),
				nothing, nothing,  
				_parse_dns_additional_record(io, header.arcount)
	end

	return _parse_dns_query_record(io, header.qdcount, len),
			_parse_dns_answer_record(io, header.ancount),
			_parse_dns_ns_record(io, header.nscount),
			_parse_dns_additional_record(io, header.arcount)
end


# Need to change early return
function _parse_dns_query_record(io::IOBuffer, qdcount::UInt16, len)::Vector{DNS_query}
	
	query_records = Vector{DNS_query}(undef, 0)

	for i in 1:qdcount
		query = readuntil(io, 0x00, keep=true)
		# Check for malformed message
		if eof(io) || (len - length(query) - 12) < 4
			return query_records
		end
		# if query is terminated by 'c01b' instead of '00'
		if last(query, 2) == [0xc0, 0x1b]
			# recover 0x00
			skip(io, -1)
		end
		qname = parse_qname(query)
		qtype = ntoh(read(io, UInt16))
		qclass = ntoh(read(io, UInt16))
		push!(query_records, DNS_query(qname, qtype, qclass))
	end
	
	return query_records

end

function _parse_dns_answer_record(io::IOBuffer, ancount::UInt16)::Vector{DNS_answer}
	
	answer_records = Vector{DNS_answer}(undef, 0)

	for i in 1:ancount
		break # before I can work out this correctly ...
		aname = readuntil(io, 0x0c, keep=true)
		if eof(io)
			answer_records
		end
		# Hm. 0x0c is a control character
		# Next character is a reference number
		# counting from start of message to retreive name ...
		aname = query_records[1].qname
		atype = ntoh(read(io, UInt16))
		aclass = ntoh(read(io, UInt16))
		push!(answer_records, DNS_answer(aname, atype, aclass))
	end
	
	return answer_records
end


function _parse_dns_ns_record(io::IOBuffer, nscount::UInt16)::Vector{DNS_nsrecord}
	# Authoritative answer (ns = nameserver)
	ns_records = Vector{DNS_nsrecord}(undef, 0)
	
	for i in 1:nscount
		nsname = readuntil(io, 0x00, keep=true)
		if eof(io)
			return ns_records
		end
		# recover 0x00
		seek(io, -1)
		nsname = parse_qname(nsname)
		nstype = ntoh(read(io, UInt16))
		nsclass = ntoh(read(io, UInt16))
		ttl = ntoh(read(io, UInt32))
		datalength = ntoh(read(io, UInt16))
		address = read(io, datalength)
		push!(ns_records, DNS_nsrecord(nsname, nstype, nsclass, ttl, datalength, address))
	end
	
	return ns_records
end


function _parse_dns_additional_record(io::IOBuffer, arcount::UInt16)::Vector{DNS_adrecord}
	# Additional record
	add_records = Vector{DNS_adrecord}(undef, 0)
	# Check for invalid arecord length
	if eof(io)
		return add_records
	end
	arecord = read(io)
	if length(arecord) <= 10
		return add_records
	else
		#recover read bytes
		skip(io, -length(arecord))
	end
	for i in 1:arcount
		arname = readuntil(io, 0x00, keep=true)
		if eof(io)
			return add_records
		end
		artype = ntoh(read(io, UInt16))
		payload_size = ntoh(read(io, UInt16))
		rcode = ntoh(read(io, UInt8))
		edns0 = ntoh(read(io, UInt8))
		z = ntoh(read(io, UInt16))
		data_length = ntoh(read(io, UInt16))
		if data_length != 0 && eof(io)
			# malformatted message ...
			return add_records
		end
		data = read(io, data_length)
		push!(add_records, DNS_adrecord(arname, artype, payload_size, rcode, edns0, z, data_length, data))
	end
	
	return add_records
end


# Include this in DNS_adrecord struct?
function parse_dns_adrecord_data(ardata::Vector{UInt8})::DNS_options
	io = IOBuffer(ardata)
	option_code = ntoh(read(io, UInt16))
	#if option_code == 10
	#	option_code = "Cookie"
	#end
	option_length = ntoh(read(io, UInt16))
	option_data = read(io, option_length)
	close(io)
	#return option_code, option_length, bytes2hex(option_data)
	return DNS_options(option_code, option_length, bytes2hex(option_data))
end

function parse_dns_flags(flags::UInt16)::DNS_flags
	qr = UInt8(flags >> 15)
	opcode = UInt8(flags << 1 >> 12)
	aa = UInt8(flags << 5 >> 15)
	tc = UInt8(flags << 6 >> 15)
	rd = UInt8(flags << 7 >> 15)
	ra = UInt8(flags << 8 >> 15)
	z = UInt8(flags << 9 >> 15)
	ad = UInt8(flags << 10 >> 15)
	cd = UInt8(flags << 11 >> 15) 
	rcode = UInt8(flags << 12 >> 12)
	
	return DNS_flags(qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode)
end


""" Parse DNS query/answer name """
function parse_qname(qname::Vector{UInt8})::String
	length(qname) == 0 ? (return string()) : nothing 
	io = IOBuffer(qname)
	query_string = string()
	peek(io) == 0x00 ? (return "<Root>") : nothing
	while true
		label = read(io, UInt8)
		for char in read(io, label)
			if char > 0x20 
				query_string *= Char(char) 
			end
		end
		eof(io) || peek(io) == 0x00 ? break : nothing
		query_string *= "."	
	end
	
	return query_string
end


""" Pretty print DNS flags """
function print_dns_flags(hex::UInt16)::Nothing
	println()
	print("DNS flag: ")
	show(hex)
	println()
	bits = bitstring(hex)
	while length(bits) < 16
		bits = "0" * bits
	end
	s = """

	|QR|  Opcode   |AA|TC|RD|RA|Z |AD|CD|  RCODE   |
	"""
	println(s)
	for bit in bits
		print(" ",bit, " ")
	end
	println("\n")
	if hex >> 15 == 1
		println("QR:\t1\t=> Query Response")
		else
		println("QR:\t0\t=> Query")
	end
	opcode = hex << 1 >> 12
	if opcode == 0
		println("OpCode:\t0\t=> Standard Query")
	end
	if opcode == 1
		println("OpCode:\t1\t=> Inverse Query")
	end
	if opcode == 2
		println("OpCode:\t2\t=> Status")
	end
	if opcode == 3
		println("OpCode:\t3\t=> Unassigned")
	end
	if opcode == 4
		println("OpCode:\t4\t=> Notify")
	end
	if opcode == 5
		println("OpCode:\t5\t=> Update")
	end
	if opcode == 6
		println("OpCode:\t6\t=> DNS Stateful operation")
	end
	if opcode > 6
		println("OpCode:\t",opcode,"\t=> Unassigned")
	end
	
	if hex << 5 >> 15 == 1
		println("AA:\t1\t=> Authoritative answer")
	end
	if hex << 6 >> 15 == 1
		println("TC:\t1\t=> Truncated message")
	end
	if hex << 7 >> 15 == 1
		println("RD:\t1\t=> Recursion desired")
	end
	if hex << 8 >> 15 == 1
		println("RA:\t1\t=> Recursion available")
	end
	if hex << 9 >> 15 == 1
		println("Z:\t1\t=> Illegal!")
	end
	if hex << 10 >> 15 == 1
		println("AD:\t1\t=> Authentication Data (RFC4035)")
	end
	if hex << 11 >> 15 == 1
		println("CD:\t1\t=> Checking Disabled (RFC4035)")
	end
	if hex << 12 >> 12 == 0
		println("Resp. code: 0\t=> No error")
		else
		print("Resp. code:\t")
		println(hex << 12 >> 12)
	end
	return nothing
end;
