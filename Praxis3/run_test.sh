rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
make -C build
for i in `seq 1 10`; 	
do
	sudo rnvs-tb-dht -s .
	wait $pid
done 

