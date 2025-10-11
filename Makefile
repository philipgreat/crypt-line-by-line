all:
	cargo build --release
static:
	cargo build --release --target x86_64-unknown-linux-musl
