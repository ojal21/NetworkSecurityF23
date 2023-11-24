all:
	@echo "Please run either 'make broker' or 'make client' or 'make merchant'"

.PHONY: broker client merchant version

broker:
	python3 sockets.py --mode broker

client:
	python3 sockets.py --mode client

merchant:
	python3 sockets.py --mode merchant

version:
	python3 --version

build:
	pip install -r requirements.txt
