# psocket-run

Trace the socket syscall and do something.

This program can set fwmark and bind socket to random source.

usage:

```bash
pfwmark-run 

USAGE:
    pfwmark-run [OPTIONS] [COMMAND]

ARGS:
    <COMMAND>    [default: bash]

OPTIONS:
    -c, --cidr <CIDR>        
    -f, --fwmark <FWMARK>    
    -h, --help               Print help information
```