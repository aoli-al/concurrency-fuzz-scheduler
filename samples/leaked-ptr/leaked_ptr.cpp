#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

int main() {
  auto* a = new uint8_t[1024*1024];

  std::jthread t1{[](uint8_t* d) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});
    d[0] = 0;
  }, a};

  std::this_thread::sleep_for(std::chrono::milliseconds{1000});

  delete[] a;
  t1.join();

  std::cout << "Exited successfully." << std::endl;
}
