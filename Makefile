debug: clean
	mkdir -p build
	cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make

release: clean
	mkdir -p build
	cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make

clean:
	rm -rf build
