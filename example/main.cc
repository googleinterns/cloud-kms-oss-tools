#include "example/hello.h"

#include <iostream>

int main(int argc, char** argv) {
  hello::Hello hello("Sundar");
  std::cout << hello.hello_string() << std::endl;
  return 0;
}