CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -O3

all: demo/demo

libblackbox.so: blackbox.cpp
	$(CXX) $(CXXFLAGS) -fPIC -shared blackbox.cpp -o libblackbox.so

demo/demo: demo/demo.cpp libblackbox.so
	$(CXX) $(CXXFLAGS) $< -L. -lblackbox -Wl,-rpath,. -I. -o $@

clean:
	rm -f demo libblackbox.so

.PHONY: all clean
