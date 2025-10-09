build:
	cargo +nightly-2025-09-29 build

build-wasmpack:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"

clean-build:
	cargo clean

verify:
	cargo +nightly-2025-09-29 creusot

clean-proofs:
	cargo +nightly-2025-09-29 creusot clean

clean: clean-build clean-proofs

test:
	cargo +nightly-2025-09-29 test
