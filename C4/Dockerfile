# Usar Ubuntu 22.10 como base
FROM ubuntu:22.10

# Cambiar los repositorios a los antiguos
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list && \
    sed -i '/security.ubuntu.com/d' /etc/apt/sources.list

# Instalar el cliente y servidor OpenSSH
RUN apt-get update && \
    apt-get install -y openssh-client openssh-server && \
    apt-get clean

# Crear el directorio necesario para el servidor OpenSSH solo si no existe
RUN test -d /var/run/sshd || mkdir /var/run/sshd

# Crear el usuario "prueba" con contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && \
    echo "prueba:prueba" | chpasswd

# Configurar el servidor SSH para permitir autenticación por contraseña
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/#PasswordAuthentication no/' /etc/ssh/sshd_config

# Exponer el puerto 22
EXPOSE 22

# Iniciar el servidor SSH
CMD ["/usr/sbin/sshd", "-D"]
