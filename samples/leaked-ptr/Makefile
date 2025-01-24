CXX = clang++
CXXFLAGS = -std=c++23 -Wall -Wextra -pthread

leaked_ptr: leaked_ptr.cpp
	$(CXX) $(CXXFLAGS) leaked_ptr.cpp -o leaked_ptr

clean:
	rm -f leaked_ptr

.PHONY: clean
