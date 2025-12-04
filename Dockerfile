# Dockerfile (Coq 공식 이미지 기반)

# 1. opam 공식 이미지를 베이스로 사용합니다.
FROM ocaml/opam:ubuntu-24.04-ocaml-5.3
# 2. 루트 사용자로 전환하여 시스템 패키지를 설치합니다.
USER root
WORKDIR /root

# 3. 시스템 의존성 및 기타 도구 설치
RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    build-essential \
    m4 \
    unzip libssl-dev libclang-dev libgmp-dev pkg-config autoconf \
    zlib1g-dev libgtksourceview-3.0-dev \
    && rm -rf /var/lib/apt/lists/*

# Typst 설치
RUN wget https://github.com/typst/typst/releases/download/v0.13.1/typst-x86_64-unknown-linux-musl.tar.xz && \
    tar -xvf typst-x86_64-unknown-linux-musl.tar.xz && \
    mv typst-x86_64-unknown-linux-musl/typst /usr/local/bin/ && \
    rm -rf typst*

# 4. 기본 사용자인 'opam'로 다시 전환합니다.
USER opam
WORKDIR /home/opam

# 5. Rust 설치
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/opam/.cargo/bin:${PATH}"

# 6. Creusot 설치
RUN ulimit -s unlimited && git clone https://github.com/creusot-rs/creusot/ \
    && cd creusot && ./INSTALL

WORKDIR /home/opam
RUN ulimit -s unlimited && eval $(opam env) && git clone https://github.com/creusot-rs/creusot-ide \
    && cd creusot-ide && opam pin creusot-lsp . -y

# 7. 작업 디렉터리 설정
WORKDIR /home/opam/workspaces/otpg
RUN rustup override set nightly-2025-11-13

# 컨테이너가 종료되지 않도록 유지
CMD ["sleep", "infinity"]
