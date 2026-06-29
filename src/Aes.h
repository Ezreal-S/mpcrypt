#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace mpcrypt {
/**
 * 16字节IV
 */
using AesIV = std::array<uint8_t, 16>;

/**
 * 32字节Key（AES-256）
 */
using AesKey = std::array<uint8_t, 32>;

enum class AesMode { AES_CBC, AES_CTR };

class AesCipher {
public:
  /**
   * 加密
   */
  static void Encrypt(std::vector<uint8_t> &data, const AesKey &key,
                      const AesIV &iv, AesMode mode);

  /**
   * 解密
   */
  static void Decrypt(std::vector<uint8_t> &data, const AesKey &key,
                      const AesIV &iv, AesMode mode);
};
} // namespace mpcrypt