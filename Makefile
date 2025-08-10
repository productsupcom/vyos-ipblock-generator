.PHONY: help build clean deb deb-docker install test detect-system

PACKAGE_NAME = vyos-ipblock
VERSION = 1.0.0

help:
	@echo "Available targets:"
	@echo "  detect-system - Detect current system"
	@echo "  deb          - Build Debian package (requires Debian/Ubuntu)"
	@echo "  deb-docker   - Build Debian package using Docker"
	@echo "  build        - Build the package"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install locally"
	@echo "  test         - Run tests"

detect-system:
	@echo "Detecting system..."
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Debian/Ubuntu detected"; \
	elif command -v yum >/dev/null 2>&1; then \
		echo "RHEL/CentOS detected"; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Fedora detected"; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "Arch Linux detected"; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "macOS detected"; \
	else \
		echo "Unknown system detected"; \
	fi

install-deps-debian:
	@echo "Installing build dependencies for Debian/Ubuntu..."
	sudo apt-get update
	sudo apt-get install -y build-essential debhelper python3-all python3-setuptools dh-python python3-requests

build:
	python3 setup.py build

deb:
	@echo "Checking if we're on Debian/Ubuntu..."
	@if ! command -v apt-get >/dev/null 2>&1; then \
		echo "Error: This system doesn't have apt-get. Use 'make deb-docker' instead."; \
		echo "Or install Docker and run: make deb-docker"; \
		exit 1; \
	fi
	@echo "Building Debian package on native system..."
	$(MAKE) install-deps-debian
	@echo "Preparing build..."
	chmod +x debian/rules
	@if [ ! -f requirements.txt ]; then \
		echo "requests>=2.25.0" > requirements.txt; \
	fi
	@if [ ! -f whitelist.txt.example ]; then \
		echo "# Example whitelist - add your networks here" > whitelist.txt.example; \
		echo "10.0.0.0/8" >> whitelist.txt.example; \
		echo "192.168.0.0/16" >> whitelist.txt.example; \
		echo "172.16.0.0/12" >> whitelist.txt.example; \
	fi
	dpkg-buildpackage -us -uc -b
	@echo "Package built successfully!"
	@echo "Install with: sudo dpkg -i ../$(PACKAGE_NAME)_$(VERSION)-1_all.deb"

deb-docker:
	@echo "Building Debian package using Docker..."
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "Error: Docker is not installed."; \
		echo "Please install Docker first: https://docs.docker.com/get-docker/"; \
		exit 1; \
	fi
	@echo "Preparing build environment..."
	chmod +x debian/rules 2>/dev/null || true
	@if [ ! -f requirements.txt ]; then \
		echo "requests>=2.25.0" > requirements.txt; \
	fi
	@if [ ! -f whitelist.txt.example ]; then \
		echo "# Example whitelist - add your networks here" > whitelist.txt.example; \
		echo "10.0.0.0/8" >> whitelist.txt.example; \
		echo "192.168.0.0/16" >> whitelist.txt.example; \
		echo "172.16.0.0/12" >> whitelist.txt.example; \
	fi
	@echo "Building in Docker container..."
	mkdir -p dist
	docker run --rm \
		-v $(PWD):/workspace \
		-v $(PWD)/dist:/dist \
		-w /workspace \
		ubuntu:22.04 \
		bash -c "export DEBIAN_FRONTEND=noninteractive && \
		apt-get update && \
		apt-get install -y build-essential debhelper python3-all python3-setuptools dh-python python3-requests && \
		chmod +x debian/rules && \
		dpkg-buildpackage -us -uc -b && \
		cp ../*.deb /dist/ && \
		chown $(shell id -u):$(shell id -g) /dist/*.deb"
	@echo "Package built successfully!"
	@echo "Package location: ./dist/$(PACKAGE_NAME)_$(VERSION)-1_all.deb"
	@echo ""
	@if ls ./dist/$(PACKAGE_NAME)_*.deb >/dev/null 2>&1; then \
		echo "✓ Package available at: $$(ls ./dist/$(PACKAGE_NAME)_*.deb)"; \
		echo ""; \
		echo "To install on this system (if Debian/Ubuntu):"; \
		echo "  sudo dpkg -i ./dist/$(PACKAGE_NAME)_*.deb"; \
		echo "  sudo apt-get install -f  # if dependencies missing"; \
		echo ""; \
		echo "To test on a Debian/Ubuntu system:"; \
		echo "  scp ./dist/$(PACKAGE_NAME)_*.deb user@debian-host:"; \
		echo "  ssh user@debian-host 'sudo dpkg -i $(PACKAGE_NAME)_*.deb'"; \
	else \
		echo "✗ Package not found in ./dist/"; \
		echo "Check the build output above for errors."; \
		exit 1; \
	fi

clean:
	python3 setup.py clean --all 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/
	rm -f ../$(PACKAGE_NAME)_*
	rm -rf dist/
	dh_clean 2>/dev/null || true

install:
	pip3 install -e .

test:
	python3 generate_blocklist.py --dry-run --verbose

# Convenience target that chooses the right method
auto-deb:
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Using native Debian build..."; \
		$(MAKE) deb; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "Using Docker build..."; \
		$(MAKE) deb-docker; \
	else \
		echo "Neither apt-get nor docker found."; \
		echo "Please install Docker to build the package."; \
		exit 1; \
	fi
