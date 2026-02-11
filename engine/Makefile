# ForgeScan Engine Build System
# Cross-platform build targets for scanner and agent binaries

.PHONY: all clean build test release scanner agent
.PHONY: linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64

# Default target
all: build

# Build all crates in debug mode
build:
	cargo build --workspace

# Run all tests
test:
	cargo test --workspace

# Build release binaries for current platform
release:
	cargo build --workspace --release

# Build only the scanner binary
scanner:
	cargo build --bin forgescan-scanner --release

# Build only the agent binary
agent:
	cargo build --bin forgescan-agent --release

# Clean all build artifacts
clean:
	cargo clean

#
# Cross-compilation targets
# Requires: rustup target add <target>
#

# Linux AMD64
linux-amd64:
	cross build --bin forgescan-agent --release --target x86_64-unknown-linux-gnu
	cross build --bin forgescan-scanner --release --target x86_64-unknown-linux-gnu

linux-amd64-agent:
	cross build --bin forgescan-agent --release --target x86_64-unknown-linux-gnu

linux-amd64-scanner:
	cross build --bin forgescan-scanner --release --target x86_64-unknown-linux-gnu

# Linux ARM64
linux-arm64:
	cross build --bin forgescan-agent --release --target aarch64-unknown-linux-gnu
	cross build --bin forgescan-scanner --release --target aarch64-unknown-linux-gnu

linux-arm64-agent:
	cross build --bin forgescan-agent --release --target aarch64-unknown-linux-gnu

# Windows AMD64
windows-amd64:
	cross build --bin forgescan-agent --release --target x86_64-pc-windows-gnu
	cross build --bin forgescan-scanner --release --target x86_64-pc-windows-gnu

windows-amd64-agent:
	cross build --bin forgescan-agent --release --target x86_64-pc-windows-gnu

# macOS AMD64
darwin-amd64:
	cargo build --bin forgescan-agent --release --target x86_64-apple-darwin
	cargo build --bin forgescan-scanner --release --target x86_64-apple-darwin

# macOS ARM64 (Apple Silicon)
darwin-arm64:
	cargo build --bin forgescan-agent --release --target aarch64-apple-darwin
	cargo build --bin forgescan-scanner --release --target aarch64-apple-darwin

#
# Package builds (creates distributable archives)
#

DIST_DIR := dist
VERSION := $(shell cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# Package for Linux AMD64
package-linux-amd64: linux-amd64 $(DIST_DIR)
	tar -czvf $(DIST_DIR)/forgescan-agent-$(VERSION)-linux-amd64.tar.gz \
		-C target/x86_64-unknown-linux-gnu/release forgescan-agent
	tar -czvf $(DIST_DIR)/forgescan-scanner-$(VERSION)-linux-amd64.tar.gz \
		-C target/x86_64-unknown-linux-gnu/release forgescan-scanner

# Package for Linux ARM64
package-linux-arm64: linux-arm64 $(DIST_DIR)
	tar -czvf $(DIST_DIR)/forgescan-agent-$(VERSION)-linux-arm64.tar.gz \
		-C target/aarch64-unknown-linux-gnu/release forgescan-agent
	tar -czvf $(DIST_DIR)/forgescan-scanner-$(VERSION)-linux-arm64.tar.gz \
		-C target/aarch64-unknown-linux-gnu/release forgescan-scanner

# Package for Windows AMD64
package-windows-amd64: windows-amd64 $(DIST_DIR)
	cd target/x86_64-pc-windows-gnu/release && \
		zip ../../../$(DIST_DIR)/forgescan-agent-$(VERSION)-windows-amd64.zip forgescan-agent.exe
	cd target/x86_64-pc-windows-gnu/release && \
		zip ../../../$(DIST_DIR)/forgescan-scanner-$(VERSION)-windows-amd64.zip forgescan-scanner.exe

#
# Development helpers
#

# Run agent with example config
run-agent:
	cargo run --bin forgescan-agent -- --scan-now --log-level debug

# Run scanner with example config
run-scanner:
	cargo run --bin forgescan-scanner -- --log-level debug

# Generate protobuf code
proto:
	cargo build -p forgescan-transport

# Check code formatting
fmt-check:
	cargo fmt --all -- --check

# Fix code formatting
fmt:
	cargo fmt --all

# Run clippy lints
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Run all CI checks
ci: fmt-check lint test
	@echo "All CI checks passed!"

# Show binary sizes
sizes: release
	@echo "Binary sizes (release build):"
	@ls -lh target/release/forgescan-agent* 2>/dev/null || true
	@ls -lh target/release/forgescan-scanner* 2>/dev/null || true

# Strip binaries for smaller size
strip: release
	strip target/release/forgescan-agent
	strip target/release/forgescan-scanner
	@echo "Stripped binary sizes:"
	@ls -lh target/release/forgescan-agent
	@ls -lh target/release/forgescan-scanner
