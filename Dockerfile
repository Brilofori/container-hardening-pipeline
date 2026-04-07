FROM debian:10

# Point to archived repositories since debian:10 is EOL
RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list

# Deliberately install vulnerable and unnecessary packages for testing
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    python2 \
    openssl \
    net-tools \
    telnet \
    ftp \
    && rm -rf /var/lib/apt/lists/*

# Insecure — container runs as root
USER root

# Insecure — exposes sensitive directory
VOLUME /etc

CMD ["/bin/bash"]
