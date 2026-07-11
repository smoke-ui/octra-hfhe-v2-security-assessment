#include "harness.hpp"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,size_t size){if(size<1)return 0;if(data[0]&1)structured_fuzz::exercise_bundle(data+1,size-1);else structured_fuzz::exercise_direct(data+1,size-1);return 0;}
