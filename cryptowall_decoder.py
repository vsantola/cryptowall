# !/usr/bin/env python
#
# Cryptowall communications decoder
# Valter Santos <vrsantos@sectoid.com
#
# Run as ./cryptowall_decoder.py /path/to/file.pcap
#

import sys
import re
from array import array
from pcapy import open_offline
from impacket import ImpactDecoder
from pprint import pprint


COMM = list()
i = 0

def Process(header, data):

	global i, COMM

	decoder = ImpactDecoder.EthDecoder()
	ether = decoder.decode(data)

	ipHeader = ether.child()
	packetType = ipHeader.child().protocol

	if packetType == 6:
		tcpHeader = ipHeader.child()

		sport = tcpHeader.get_th_sport()
		dport = tcpHeader.get_th_dport()

		if ((tcpHeader.get_PSH() and tcpHeader.get_ACK()) and (sport == 80 or dport == 80)):
			p = { 'src_ip': ipHeader.get_ip_src(),
			      'src_port': sport, 
			      'dst_ip': ipHeader.get_ip_dst(),
			      'dst_port': dport, 
			      'host': None, 
			      'key': None, 
			      'data': None
			     }
			payload = GetPayload(tcpHeader)

			# victim requests			
			if dport == 80:

				# reads key from victim request querystring
				# POST /wp-includes/certificates/3.php?q=isoh0is3ia56e HTTP/1.1
				m = re.search('POST (.*)\?[a-z]=(.+?) HTTP', payload)
				if m:
					p['key'] = m.group(2)

					# Host: healthyairmasters.com
					m1 = re.search('Host: (.*)\r\n', payload)
					if m1:
						p['host'] = m1.group(1)

					COMM.append(p)

				# reads data request from POST body
				# v=5961bc32a20b12e7ac81e52253fc1a450211d2b07fb29073d661f1becf02ee77d024eff456a8c55cd0fa2fc34dc554ab39eb4613e9
				m = re.search('^[a-z]=(.*)', payload)
				if m:
					data = m.group(1)

					try:
						COMM[i]['data'] = data
						i = i + 1
					except:
						pass

			# c2 response
			if sport == 80 and i>0:

				if p['src_ip'] == COMM[i-1]['dst_ip'] and \
				   p['src_port'] == COMM[i-1]['dst_port'] and \
				   p['dst_ip'] == COMM[i-1]['src_ip'] and \
				   p['dst_port'] == COMM[i-1]['src_port']:

					# check if is a real response from a live Cryptowall C2
					http_200 = re.search('^HTTP\/1\.1 200 OK', payload)
					if http_200:
						
						# ignore the PNG response that the C2 deliveries - it's the payment instruction in a PNG file
						png_response = re.search('PNG', payload)
						if not png_response:
							p['key'] = COMM[i-1]['key']
							p['host'] = COMM[i-1]['host']

							# 'HTTP/1.1 200 OK\r\nServer: nginx/1.8.0\r\nDate: Tue, 29 Sep 2015 18:03:04 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\ne\r\n689c4ff2c8ba6d\r\n'
							data = re.search('(.*)Connection: close\r\n\r\n(.*)\r\n(.*)\r\n', payload)
							if data:
								p['data'] = data.group(3)
								COMM.append(p)
								i = i + 1 



	return True

def GetPayload(tcpHeader):

	payload_decimal = tcpHeader.child().get_bytes().tolist()
	ascii = []

	for decByte in payload_decimal:
		if decByte in range(9,14) or decByte in range(32,127):
			hexByte = str(hex(decByte)).lstrip("0x")
			if len(hexByte) == 1:
				hexByte = "0" + hexByte
			asciiByte = hexByte.decode('hex')
			ascii.append(asciiByte)

	payload_ascii = ''.join(ascii)
	return payload_ascii


def filefilter(pcapfile):

	try:
		print("Reading pcap file %s" % pcapfile)
		packetReader = open_offline(pcapfile)
	except Exception as e:
		print("Error opening pcap file: %s" % str(e))
		return 0

	packetReader.loop(0, Process)


def rc4_ksa(key):
  keylen = len(key)
  S = range(256)
  j = 0
  for i in range(256):
    j = (j+S[i]+key[i%keylen])%256
    S[i], S[j] = S[j], S[i]
  return S

def rc4_prng_and_xor(ct, S_):
  S = list(S_)
  pt = []
  ctlen = len(ct)
  i = 0
  j = 0
  for c in ct:
    i = (i+1)%256
    j = (j+S[i])%256
    S[i], S[j] = S[j], S[i]
    k = (S[i]+S[j])%256
    pt.append(c^S[k])
  return pt

def rc4_decode(r):

	try:
		key_sorted = sorted(bytearray(r['key']))
		ddata = bytearray(r['data'].decode("hex"))

		S = rc4_ksa(key_sorted)
		plain = rc4_prng_and_xor(ddata, S)

		print "%s:%s => %s:%s [%s] - %s" % (r['src_ip'], r['src_port'], r['dst_ip'], r['dst_port'], r['host'], array('B', plain).tostring())

	except:
		pass

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s <pcapfile>" % sys.argv[0]
        sys.exit(1)

    print("-: Cryptowall communications decoder :-")
    filefilter(sys.argv[1])

    for c in COMM:
    	if 'key' in c and 'data' in c:
    		rc4_decode(c)


    
