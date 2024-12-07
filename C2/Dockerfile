# Usar Ubuntu 18.10 como base
FROM ubuntu:18.10

# Actualizar los repositorios para usar los de old-releases.ubuntu.com
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list

# Eliminar o comentar el repositorio de seguridad que ya no existe
RUN sed -i '/security.ubuntu.com/d' /etc/apt/sources.list

# Instalar el cliente OpenSSH
RUN apt-get update && apt-get install -y openssh-client && apt-get clean

# Mantener el contenedor en modo interactivo
CMD ["bash"]
