CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -O3

all: extractor demo/demo

libblackbox.so: blackbox.cpp internal.h
	$(CXX) $(CXXFLAGS) -fPIC -shared blackbox.cpp -o libblackbox.so -g

extractor: extractor.cpp internal.h
	$(CXX) $(CXXFLAGS) $< -o $@ -g

demo/demo: demo/demo.cpp libblackbox.so
	$(CXX) $(CXXFLAGS) $< -L. -lblackbox -Wl,-rpath,. -I. -o $@ -g

clean:
	rm -f extractor demo/demo libblackbox.so

.PHONY: all clean
