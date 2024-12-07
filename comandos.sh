cd .\OneDrive\Escritorio\CodigoLabCripto5\
-------
docker build -t ubuntu16-ssh ./C1
docker run -dit --name C1 ubuntu16-ssh

docker build -t ubuntu18-ssh ./C2
docker run -dit --name C2 ubuntu18-ssh

docker build -t ubuntu20-ssh ./C3
docker run -dit --name C3 ubuntu20-ssh

docker build -t ubuntu22-ssh ./C4
docker run -dit --name C4 ubuntu22-ssh
-------
docker exec -it C1 bash
docker exec -it C2 bash
docker exec -it C3 bash
docker exec -it C4 bash

apt-get update && apt-get install -y net-tools

docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' C4
ssh prueba@<IP_del_contenedor> -p 22

ssh prueba@172.17.0.2 -p 22


ssh -V
-------
docker run -d -p 2222:22 --name C4 ubuntu22-ssh


ssh prueba@localhost -p 2222



apt-get update
apt-get install -y iputils-ping
ping 172.17.0.1

docker run -d -p 2222:22 --name C4 ubuntu22-ssh

ssh prueba@172.17.0.3 -p 22



apt-get update && apt-get install -y tcpdump
---------------

docker inspect C4 | findstr "IPAddress"
docker inspect C1 | findstr "IPAddress"


apt-get update && apt-get install -y tcpdump


docker exec -it C4 tcpdump -i eth0 tcp port 22 -w /tmp/C4.pcap

ssh prueba@172.17.0.3 -p 22

ls
echo "Prueba de tráfico SSH" > prueba.txt

docker cp C4:/tmp/C4.pcap ./C4.pcap

----------------

--optener ip del contenedor
docker inspect C1 | findstr "IPAddress"
docker inspect C2 | findstr "IPAddress"
docker inspect C3 | findstr "IPAddress"
docker inspect C4 | findstr "IPAddress"

--instalar tcpdump para capturar
apt-get update && apt-get install -y tcpdump

--capturar en cmd1, en terminal  captura paquetes ente contenedor y servidor ssh a travez del puerto 22
docker exec -it C1 tcpdump -i eth0 tcp and host 172.17.0.5 and port 22 -w /tmp/C1_a_S1.pcap
docker exec -it C2 tcpdump -i eth0 tcp and host 172.17.0.5 and port 22 -w /tmp/C2_a_S1.pcap
docker exec -it C3 tcpdump -i eth0 tcp and host 172.17.0.5 and port 22 -w /tmp/C3_a_S1.pcap
docker exec -it C4 tcpdump -i eth0 tcp and host 172.17.0.5 and port 22 -w /tmp/C4_a_S1.pcap

--dentro de cada contenedor en cmd 2,dentro del contenedor a muestrear, generar el trafico
ssh prueba@172.17.0.3 -p 22

ssh prueba@172.17.0.3
ssh prueba@localhost

ping 172.17.0.3

--
apt-get update && apt-get install -y tcpdump
apt update && apt install -y telnet
apt-get update
apt-get install -y iputils-ping

--c1 a s1
tcpdump -i eth0 host 172.17.0.3 -w /tmp/c1-hasta-c4.pcap
ls /tmp/c1-hasta-s1.pcap
docker cp C1:/tmp/c1-hasta-s1.pcap ./c1-hasta-s1.pcap
--c2 a s1
tcpdump -i eth0 host 172.17.0.3 -w /tmp/c2-hasta-s1.pcap
ls /tmp/c2-hasta-s1.pcap
docker cp C2:/tmp/c2-hasta-s1.pcap ./c2-hasta-s1.pcap
--c3 a s1
tcpdump -i eth0 host 172.17.0.3 -w /tmp/c3-hasta-s1.pcap
ls /tmp/c3-hasta-s1.pcap
docker cp C3:/tmp/c3-hasta-s1.pcap ./c3-hasta-s1.pcap
--c4 a s1
tcpdump -i lo port 22 -w /tmp/c4-a-s1.pcap
ls /tmp/c4-hasta-s1.pcap
docker cp C4:/tmp/c4-hasta-s1.pcap ./c4-hasta-s1.pcap



-
rm /tmp/c4-a-s1.pcap

docker run --privileged -it C4 bash
-------


docker exec -it C1 bash
docker exec -it C2 bash
docker exec -it C3 bash
docker exec -it C4 bash

ssh -V




apt update
apt install mitmproxy
-----

--cmd1 
tcpdump -i eth0 port 22 -w /tmp/TraficoReplica2.pcap
docker cp C1:/tmp/TraficoReplica2.pcap ./TraficoReplica2.pcap
--cmd2
docker cp send_ssh.py C1:/root/send_ssh.py
python3 /root/send_ssh.py
ls /root/send_ssh.py

python3 /root/send_ssh.py

--cmd1
apt update
apt install scapy

apt install python3
apt install python3-pip

apt install python3-dev libpcap-dev
python3 -m pip install scapy

--
apt install python3.8 python3.8-dev python3.8-venv


apt-get update
apt-get install python3-scapy



