FROM ubuntu:latest

# Аргументы сборки с значениями по умолчанию
ARG ARCH=amd64
ARG BUILD_TYPE=release

# Предотвращаем интерактивные запросы при установке пакетов
ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y \
    mingw-w64 \
    mingw-w64-tools \
    python3 \
    python3-pip \
    python3-venv \
    git \
    bash \
    cpio \
    wget \
    curl \
    # Инструменты сборки
    cmake \
    ninja-build \
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    # LLVM/Clang (нужен для seL4)
    clang \
    llvm \
    lld \
    # Дополнительные утилиты
    libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

# Настройка Python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Устанавливаем Python-пакеты
RUN pip3 install --no-cache-dir \
    --break-system-packages \
    jinja2 \
    future \
    ply \
    setuptools \
    six \
    lxml

WORKDIR /workspace

# Клонируем репозиторий
RUN git clone https://github.com/Endlad2/NeptuneOS.git

WORKDIR /workspace/NeptuneOS

# Инициализируем сабмодули
RUN git submodule update --init --recursive

# Делаем build.sh исполняемым
RUN bash build.sh [${ARCH}] [${BUILD_TYPE}]
RUN mkiso.sh [${ARCH}] [${BUILD_TYPE}]

# Запускаем сборку с переданными аргументами


CMD ["/bin/bash"]
