# Dockerfile (Coq 공식 이미지 기반)

# 1. Coq 공식 이미지를 베이스로 사용합니다.
# 이 이미지에는 opam, ocaml, coq가 이미 설치 및 설정되어 있습니다.
FROM coqorg/coq:8.20-native-flambda

# 2. 루트 사용자로 전환하여 시스템 패키지를 설치합니다.
USER root

# 3. 시스템 의존성 및 기타 도구 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    build-essential \
    m4 \
    && rm -rf /var/lib/apt/lists/*

# Typst 설치
RUN wget https://github.com/typst/typst/releases/download/v0.13.1/typst-x86_64-unknown-linux-musl.tar.xz && \
    tar -xvf typst-x86_64-unknown-linux-musl.tar.xz && \
    mv typst-x86_64-unknown-linux-musl/typst /usr/local/bin/ && \
    rm -rf typst*

# 4. 기본 사용자인 'coq'로 다시 전환합니다.
USER coq
WORKDIR /home/coq

# 5. Rust 설치
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/coq/.cargo/bin:${PATH}"

# 6. coq-of-rust 설치
# Coq 환경이 이미 준비되어 있으므로, 소스 코드 빌드 및 설치만 진행합니다.
RUN ulimit -s unlimited && git clone https://github.com/formal-land/coq-of-rust.git \
    && cd coq-of-rust \
    && eval $(opam env) \
    && cargo install --path lib/ \
    && cd CoqOfRust \
    && opam install . --deps-only -y && make

# 7. 작업 디렉터리 설정
WORKDIR /home/coq/work

# 컨테이너가 종료되지 않도록 유지
CMD ["sleep", "infinity"]
