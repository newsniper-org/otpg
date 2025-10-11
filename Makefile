build:
	cargo +nightly-2025-10-01 build

build-wasmpack:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"

clean-build:
	cargo +nightly-2025-10-01 clean

verify:
	cargo +nightly-2025-10-01 creusot

clean-proofs:
	rm -rfd verif

clean: clean-build clean-proofs

test:
	cargo +nightly-2025-10-01 test
