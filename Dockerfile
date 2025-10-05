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
    unzip libssl-dev libclang-dev libgmp-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Typst 설치
RUN wget https://github.com/typst/typst/releases/download/v0.13.1/typst-x86_64-unknown-linux-musl.tar.xz && \
    tar -xvf typst-x86_64-unknown-linux-musl.tar.xz && \
    mv typst-x86_64-unknown-linux-musl/typst /usr/local/bin/ && \
    rm -rf typst*

# 4. 기본 사용자인 'opam'로 다시 전환합니다.
USER opam
WORKDIR /home/opam

# 5. Rust 및 Z3 설치
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
COPY get_fstar_z3.sh .
RUN sudo chmod +x get_fstar_z3.sh
RUN sudo ./get_fstar_z3.sh /usr/local/bin
ENV PATH="/home/opam/.cargo/bin:${PATH}"

# 6. fstar 설치
RUN ulimit -s unlimited && eval $(opam env) && opam install fstar

# 7. cargo-hax 설치
RUN ulimit -s unlimited && cargo +nightly-2024-12-07 install cargo-hax

# 8. 작업 디렉터리 설정
WORKDIR /home/opam/workspaces/otpg
RUN rustup override set nightly-2024-12-07

# 컨테이너가 종료되지 않도록 유지
CMD ["sleep", "infinity"]
