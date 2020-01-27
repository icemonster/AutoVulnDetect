# AutoVulnDetect
This repository contains a symbolic executor capable of detecting common vulnerabilities in x86 binaries

## Example (after compiling examples/vuln.c)
### Analyse a binary called "vuln" that takes two arguments (--args). 
### One is the string "whatever" and the other has 32 unknown bytes (Sym32). 
### Try to craft an exploit (-e) that redirects execution flow (--RET_ADDR) to address 0x08048516

```
./AutoVulnDetect examples/vuln --args whatever Sym32 --RET_ADDR 0x08048516 -e
```

### This will create a file called exploit.py with the crafted exploit.
### Exploiting vuln is as simple as calling `python3 exploit.py` now