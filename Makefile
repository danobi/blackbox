CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -Wpedantic -O3

all: demo

libblackbox.so: blackbox.cpp
	$(CXX) $(CXXFLAGS) -fPIC -shared blackbox.cpp -o libblackbox.so

demo: demo.cpp libblackbox.so
	$(CXX) $(CXXFLAGS) demo.cpp -L. -lblackbox -Wl,-rpath,. -o demo

clean:
	rm -f demo libblackbox.so

.PHONY: all clean
