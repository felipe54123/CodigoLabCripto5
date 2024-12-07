# Usar Ubuntu 16.10 como base
FROM ubuntu:16.10

# Reemplazar repositorios y eliminar referencias a los de seguridad
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list && \
    sed -i '/security.ubuntu.com/d' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y openssh-client && \
    apt-get clean

# Mantener el contenedor en modo interactivo
CMD ["bash"]
