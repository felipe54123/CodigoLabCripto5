# Usar Ubuntu 20.10 como base
FROM ubuntu:20.10

# Cambiar los repositorios a los antiguos
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list && \
    sed -i '/security.ubuntu.com/d' /etc/apt/sources.list

# Instalar el cliente OpenSSH
RUN apt-get update && apt-get install -y openssh-client && apt-get clean

# Mantener el contenedor en modo interactivo
CMD ["bash"]
