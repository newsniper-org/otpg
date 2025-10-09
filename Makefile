build:
	cargo build

build-wasmpack:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --features "wasm-bindgen"

clean-build:
	cargo clean

verify-fstar-%:
	./verify-fstar.sh "$(patsubst verify-fstar-%,%,$@)"

.PHONY: verify-fstar
verify-fstar: verify-fstar-core

verify-coq-%:
	./verify-coq.sh "$(patsubst verify-fstar-%,%,$@)"

.PHONY: verify-coq
verify-coq: verify-coq-core


clean-%-proofs:
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/$(patsubst clean-%-proofs,Otpg_%,$@).*.fst
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/.depend
	rm -f $(patsubst clean-%-proofs,otpg-%,$@)/proofs/fstar/extraction/hax.fst.config.json
	rm -rfd $(patsubst clean-%-proofs,otpg-%,$@)/proofs/coq

clean-proofs: clean-core-proofs
	rm -rfd .fstar-cache
	rm -rfd .cache.boot

clean: clean-build clean-proofs
