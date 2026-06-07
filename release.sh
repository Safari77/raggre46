#!/bin/sh
cargo clippy && cargo build --release && cargo release patch --no-publish --execute
