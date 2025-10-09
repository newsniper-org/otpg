build:
	cargo build

build-wasmpack:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"

clean-build:
	cargo clean

verify:
	cargo creusot

clean-proofs:
	cargo creusot clean

clean: clean-build clean-proofs

test:
	cargo test
