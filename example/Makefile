build:
	mkdir -p docker
	cp ../build/bin/geth docker
	cp Dockerfile.in docker/Dockerfile
	docker build -t geth docker

init:
	../build/bin/geth --identity node1 init Genesis.json --datadir data1
	../build/bin/geth --identity node2 init Genesis.json --datadir data2
	cp nodekey1 data1/geth/nodekey
	cp nodekey2 data2/geth/nodekey

clean:
	rm -rf docker
	sudo rm -rf data1 data2
	docker rm -f geth1 geth2

	
