#include "SessionKeyGenerator.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    SessionKeyGenerator keyGen;
    const std::array<std::uint8_t, 32> customMasterKey = {
        0xAA, 0x01, 0x02, 0x03, 0xBB, 0x05, 0x06, 0x07,
        0xCC, 0x09, 0x0A, 0x0B, 0xDD, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
        0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43
    };
    keyGen.setMasterKey(customMasterKey);

    const std::vector<std::uint8_t> context = {'E', 'C', 'U', '-', 'A', '1'};
    const auto sessionKey = keyGen.deriveSessionKey(context, 0x1001U, 32);
    const auto hmac = keyGen.computeHmacSha256(context, sessionKey);


}
