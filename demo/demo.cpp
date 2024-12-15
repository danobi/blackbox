#include <iostream>

#include "blackbox.h"

int main() {
  blackbox::write("hello world!");
  blackbox::write(123);
  blackbox::write("key1", "val1");
  blackbox::dump(std::cout);
}
