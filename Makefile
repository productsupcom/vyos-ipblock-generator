# Makefile for VyOS Blocklist Generator

PACKAGE_NAME = vyos-ipblock

.PHONY: all clean

all: clean

clean:
	@echo "Cleaning build artifacts..."
	# Python build artifacts
	python3 setup.py clean --all 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/
	
	# Debian build artifacts
	rm -rf debian/.debhelper/ debian/vyos-ipblock/
	rm -f debian/files debian/*.substvars debian/*.debhelper.log
	
	# Package files
	rm -f ../$(PACKAGE_NAME)_*
	rm -rf dist/
	
	# Temporary files
	rm -f requirements.txt.tmp whitelist.txt.example.tmp
	
	# Clean with dh_clean if available
	dh_clean 2>/dev/null || true
	
	@echo "Build artifacts cleaned successfully"