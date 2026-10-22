# Dockerfile for building patched PHP 5.6.40 with session UAF fix
FROM debian:jessie-slim

# Use archive repositories for Debian Jessie EOL
RUN echo "deb http://archive.debian.org/debian jessie main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main contrib non-free" >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

RUN apt-get update && apt-get install -y --force-yes \
    build-essential \
    curl \
    patch \
    libxml2-dev \
    libssl-dev \
    libbz2-dev \
    libcurl4-openssl-dev \
    libjpeg-dev \
    libpng-dev \
    libmcrypt-dev \
    libreadline-dev \
    apache2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# Download PHP 5.6.40 source
RUN curl -sL https://www.php.net/distributions/php-5.6.40.tar.gz | tar -xz

WORKDIR /usr/src/php-5.6.40

# Copy and apply the security patch
COPY patches/php-5.6.x-session-upload-progress-uaf.patch /tmp/
RUN patch -p1 < /tmp/php-5.6.x-session-upload-progress-uaf.patch

# Configure and compile
RUN ./configure \
    --prefix=/usr/local/php56 \
    --with-config-file-path=/usr/local/php56/etc \
    --enable-fpm \
    --enable-session \
    --enable-mbstring \
    --with-curl \
    --with-openssl \
    --with-zlib \
    --enable-zip

RUN make -j$(nproc)

# Run session regression tests to ensure stability
RUN make test TESTS="ext/session/tests/"

CMD ["/usr/src/php-5.6.40/sapi/fpm/php-fpm", "-F"]
