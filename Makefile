build:
	ifeq ($(WASMPACK),1)
		RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"
	else
		cargo build

clean-build:
	cargo clean

clean: clean-build
