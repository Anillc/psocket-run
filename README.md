# psocket-run

Trace the socket syscall and do something.

This program can do the following things:

1. set fwmark for socket
2. bind random source of socket
3. add http proxy for socket

(Only supports x86_64.)

usage:

```bash
psocket-run [OPTIONS] [COMMAND]

ARGS:
    <COMMAND>    [default: bash]

OPTIONS:
    -a, --attach <ATTACH>    
    -c, --cidr <CIDR>        
    -f, --fwmark <FWMARK>    
    -h, --help               Print help information
    -n, --no-kill            
    -p, --proxy <PROXY>      
    -v, --verbose            
```