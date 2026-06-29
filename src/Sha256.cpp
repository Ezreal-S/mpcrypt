#include "Sha256.h"
#include "picosha2/picosha2.h"

namespace mpcrypt {
Sha256Hash Sha256(const void *data, size_t size) {
  Sha256Hash hash{};

  picosha2::hash256(reinterpret_cast<const uint8_t *>(data),
                    reinterpret_cast<const uint8_t *>(data) + size,
                    hash.begin(), hash.end());

  return hash;
}

Sha256Hash Sha256(const std::string &text) {
  return Sha256(text.data(), text.size());
}

std::string Sha256ToHex(const Sha256Hash &hash) {
  return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}
} // namespace mpcrypt