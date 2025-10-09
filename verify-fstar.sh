#!/usr/bin/env bash

cd "otpg-$1"
cargo hax into fstar
cd proofs/fstar/extraction
ulimit -s unlimited && OTHERFLAGS="--lax" make
