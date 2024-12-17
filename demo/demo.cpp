#include <chrono>
#include <iostream>
#include <thread>

#include "blackbox.h"

int main() {
  blackbox::init();
  blackbox::write("hello world!");
  blackbox::write(123);
  blackbox::write("key1", "val1");
  blackbox::dump(std::cout);

  std::this_thread::sleep_for(std::chrono::seconds(100));
}
