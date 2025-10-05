build:
	cargo build

build-wasmpack:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"

clean-build:
	cargo clean

verify-%:
	./verify.sh "$(patsubst verify-%,%,$@)"

.PHONY: verify
verify: verify-core

clean-%-proofs:
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/$(patsubst clean-%-proofs,Otpg_%,$@).*.fst
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/.depend
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/hax.fst.config.json

clean-proofs: clean-core-proofs
	rm -rfd .fstar-cache
	rm -rfd .cache.boot

clean: clean-build clean-proofs
