#include "Aes.h"
#include <cstring>

extern "C"{
    #include "tinyaes/aes.h"
}

namespace mpcrypt {
static void XorStream(uint8_t *data, size_t size, const AesKey &key,
                      const AesIV &iv) {
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key.data(), iv.data());

  AES_CTR_xcrypt_buffer(&ctx, data, size);
}

static void CbcEncrypt(std::vector<uint8_t> &data, const AesKey &key,
                       const AesIV &iv) {
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key.data(), iv.data());

  AES_CBC_encrypt_buffer(&ctx, data.data(), data.size());
}

static void CbcDecrypt(std::vector<uint8_t> &data, const AesKey &key,
                       const AesIV &iv) {
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key.data(), iv.data());

  AES_CBC_decrypt_buffer(&ctx, data.data(), data.size());
}

void AesCipher::Encrypt(std::vector<uint8_t> &data, const AesKey &key,
                        const AesIV &iv, AesMode mode) {
  if(mode == AesMode::AES_CTR) {
    XorStream(data.data(), data.size(), key, iv);
  } else {
    CbcEncrypt(data, key, iv);
  }
}

void AesCipher::Decrypt(std::vector<uint8_t> &data, const AesKey &key,
                        const AesIV &iv, AesMode mode) {
  if(mode == AesMode::AES_CTR) {
    XorStream(data.data(), data.size(), key, iv);
  } else {
    CbcDecrypt(data, key, iv);
  }
}
} // namespace mpcrypt