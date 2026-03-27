#!/bin/sh
cargo build --release && cargo release patch --no-publish --execute
