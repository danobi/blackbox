CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -O3 -fsanitize=address

all: extractor/extractor demo/demo

libblackbox.so: blackbox.cpp internal.h
	$(CXX) $(CXXFLAGS) -fPIC -shared blackbox.cpp -o libblackbox.so -g

extractor/extractor: extractor/extractor.cpp internal.h
	$(CXX) $(CXXFLAGS) $< -I. -o $@ -g

demo/demo: demo/demo.cpp libblackbox.so
	$(CXX) $(CXXFLAGS) $< -L. -lblackbox -Wl,-rpath,. -I. -o $@ -g

clean:
	rm -f extractor/extractor demo/demo libblackbox.so

.PHONY: all clean
