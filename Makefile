all:
	cargo build --release
static:
	# needs to build on linux
	cargo build --release --target x86_64-unknown-linux-musl
