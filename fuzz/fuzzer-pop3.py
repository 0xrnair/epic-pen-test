#!/usr/bin/env python

import os,sys
import socket
'''
Python Service fuzzer for POP3
'''

if len(sys.argv) != 3:
	print "[*] Usage -> ./fuzz <IP address> <port>"
	sys.exit(-1)	

ip = sys.argv[1]
port = sys.argv[2]

os.system('clear')
	
# Create an array of buffers from 10 to 2000, with increments of 20.
buffer=["A"]
counter=100

while len(buffer) <= 30:
     buffer.append("A"*counter)
     counter=counter+200

for string in buffer:
     print "\n\nFuzzing PASS with %s bytes." % len(string)

     s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     connect=s.connect((ip,port))         # Connect to IP on any port

     s.recv(1024)                                 # Receive reply.
     s.send('USER test\r\n')                      # Send username 'test'.
     s.recv(1024)                                 # Receive reply.
     s.send('PASS ' + string + '\r\n')            # Send password 'PASS' plus random buffer.
     s.send('QUIT\r\n')                           # Send command 'QUIT'.
     s.close()                                    # Close socket.
