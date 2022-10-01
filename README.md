# psocket-run

Trace the socket syscall and do something.

This program can set fwmark and bind socket to random source.

(Only support x86_64.)

usage:

```bash
psocket-run 

USAGE:
    psocket-run [OPTIONS] [COMMAND]

ARGS:
    <COMMAND>    [default: bash]

OPTIONS:
    -a, --attach <ATTACH>    
    -c, --cidr <CIDR>        
    -f, --fwmark <FWMARK>    
    -h, --help               Print help information
```