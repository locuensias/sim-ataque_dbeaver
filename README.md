Este codigo lo que hace es simular un ataque entre una base de datos y un cliente a traves de contaminar paquetes mysql dentro de una red controlada ya que se usaran contenedores docker. 

## Requisitos Previos

* Docker instalado en un sistema operativo Linux.
* Git instalado en la máquina local.
* Una base de datos MYSQL

## Descripción del Entorno

Este proyecto simula una arquitectura de red de tres nodos utilizando contenedores Docker, comunicados a través de una red virtual privada:
1.  **Contenedor Servidor (`mysql-server`):** Ejecuta una instancia de MySQL Server.
2.  **Contenedor Cliente (`dbeaver-client`):** Ejecuta el cliente de base de datos DBeaver. Para este codigo se uso ese cliente pero "en teoria" debe de funcionar para cualquier cliente que se comunique con una base de datos MYSQL.
3.  **Contenedor Atacante (`scapy-attacker`):** Ejecuta los scripts de Scapy para realizar los ataques MitM.

## Instrucciones de Instalación y Ejecución
### 1. Preparación del Entorno Base

Antes de ejecutar los ataques, es necesario configurar el entorno cliente-servidor.

**a) Configurar y lanzar el Servidor MySQL:**
El servidor se lanza utilizando la imagen oficial de MySQL y un script `init.sql` (incluido en este repositorio) que prepara una base de datos de ejemplo.

* Primero, crear la red virtual si no existe:
    docker network create tarea-net
    
* Luego, lanzar el servidor (asegúrese de tener `init.sql` en la carpeta):
   
    docker run -d --name mysql-server --network tarea-net -v "$(pwd)/init.sql:/docker-entrypoint-initdb.d/init.sql" -e MYSQL_ROOT_PASSWORD=mi_password_root mysql:8.0
   

**b) Construir la imagen del Cliente DBeaver:**
Para ejecutar el cliente, se debe construir una imagen personalizada (en este caso Dbeaver). Se necesita el archivo de instalación `.deb` de DBeaver, que se puede descargar desde el [sitio web oficial](https://dbeaver.io/download/).

* Cree un `Dockerfile` con el siguiente contenido:
    # Dockerfile ejemplo DBeaver
        FROM ubuntu:22.04
        ENV DEBIAN_FRONTEND=noninteractive
        RUN apt-get update && apt-get install -y libgtk-3-0 libwebkit2gtk-4.0-37 default-jre wget --no-install-recommends && rm -rf /var/lib/apt/lists/*
        COPY dbeaver-ce_*.deb /tmp/dbeaver.deb
        RUN dpkg -i /tmp/dbeaver.deb
        CMD ["/usr/share/dbeaver-ce/dbeaver"]

  
* Coloque el `Dockerfile` y el archivo `.deb` en una carpeta y construya la imagen:

    docker build -t mi-dbeaver-local .
 

### 2. Ejecución del Ataque

**a) Preparar la Carpeta del Atacante:**
¡Este repositorio contiene todos los archivos necesarios!. Al clonarlo, tendrás la estructura lista.

mkdir ~/scapy-attack
cd ~/scapy-attack
nano Dockerfile
    (
    FROM python:3.9-slim
    RUN apt-get update && apt-get install -y tcpdump net-tools iproute2
    RUN pip install scapy
    WORKDIR /usr/src/app
    CMD ["bash"]
    )
    nano mitm_attack.py

**b) Construir la Imagen del Atacante:**


* Para construir la imagen, ejecute el siguiente comando en la raíz del repositorio:
    docker build -t scapy-attacker .


**c) Ejecutar un Ataque:**
* Asegúrese de que los contenedores `mysql-server` y `dbeaver-client` estén corriendo.
* Obtenga las IPs de `mysql-server` y `dbeaver-client` con el comando `docker inspect tarea-net en el caso de ejemplo`.
* Edite uno de los scripts de ataque (ej. `attack_fuzz_random.py`) con las IP obtenidas.
    [Edición del script de ataque]
* Lance el contenedor atacante, montando el script que desea ejecutar:
            
  ej1: `attack_fuzz_random.py`
        
        cd ~/scapy-attack

        docker run -it --rm --name scapy-attacker --network tarea-net --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 -v "$(pwd)/attack_fuzz_random.py:/usr/src/app/attack_fuzz_random.py" scapy-attacker bash
    
* Dentro del contenedor del atacante, ejecute el script:
    python3 attack_fuzz_random.py


  ej2: `attack_force_quit.py`
    
        cd ~/scapy-attack

        docker run -it --rm --name scapy-attacker --network tarea-net --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 -v "$(pwd)/attack_force_quit.py:/usr/src/app/attack_force_quit.py" scapy-attacker bash
    
* Dentro del contenedor del atacante, ejecute el script:
    python3 attack_force_quit.py

## Autores

* Erick Román
* Benjamin Yañez
