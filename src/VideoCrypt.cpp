#include "VideoCrypt.h"
#include "Aes.h"
#include "Sha256.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

// 跨平台大文件 + UTF-8 路径
#ifdef _WIN32
#include <windows.h>
#include <stringapiset.h>
#include <wincrypt.h>


#pragma comment(lib, "advapi32.lib")

#define MPC_FSEEK(fp, offset, origin) _fseeki64(fp, offset, origin)
#define MPC_FTELL(fp) _ftelli64(fp)
using mpc_off_t = int64_t;

static std::wstring utf8_to_wstring(const char *str) {
  if (!str)
    return L"";
  int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
  if (len <= 0)
    return L"";
  std::wstring result(len - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], len);
  return result;
}
static FILE *mp_fopen(const char *path, const char *mode) {
  std::wstring wpath = utf8_to_wstring(path);
  std::wstring wmode = utf8_to_wstring(mode);
  return _wfopen(wpath.c_str(), wmode.c_str());
}
#else
#include <fcntl.h>
#include <unistd.h>

#define MPC_FSEEK(fp, offset, origin) fseeko(fp, offset, origin)
#define MPC_FTELL(fp) ftello(fp)
using mpc_off_t = off_t;

static inline FILE *mp_fopen(const char *path, const char *mode) {
  return fopen(path, mode);
}
#endif

namespace mpcrypt {

// ===================== 常量 =====================
static constexpr size_t HEAD_ENCRYPT_SIZE = 4 * 1024 * 1024; // 4 MB
static constexpr uint32_t FOOTER_MAGIC = 0x4D504345;         // "MPCE"
static constexpr uint32_t PADDING_MIN = 16 * 1024 * 1024;                // 16MB
static constexpr uint32_t PADDING_MAX = 64 * 1024 * 1024;           // 64MB

// ===================== 随机数 =====================
static bool generate_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
  HCRYPTPROV hProv = 0;
  if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT))
    return false;
  BOOL ok = CryptGenRandom(hProv, (DWORD)len, buf);
  CryptReleaseContext(hProv, 0);
  return ok != FALSE;
#else
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return false;
  size_t total = 0;
  while (total < len) {
    ssize_t r = read(fd, buf + total, len - total);
    if (r <= 0) {
      close(fd);
      return false;
    }
    total += r;
  }
  close(fd);
  return true;
#endif
}

template <size_t N> static bool fill_random(std::array<uint8_t, N> &arr) {
  return generate_random_bytes(arr.data(), N);
}

static uint32_t random_uint32_range(uint32_t min, uint32_t max) {
  if (min >= max)
    return min;
  static std::random_device rd;
  static std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dist(min, max);
  return dist(gen);
}

// ===================== 路径工具 =====================
static std::string extract_filename(const std::string &path) {
  const char *s1 = strrchr(path.c_str(), '/');
  const char *s2 = strrchr(path.c_str(), '\\');
  const char *last = (s1 > s2) ? s1 : s2;
  return last ? std::string(last + 1) : path;
}
static std::string extract_directory(const std::string &path) {
  const char *s1 = strrchr(path.c_str(), '/');
  const char *s2 = strrchr(path.c_str(), '\\');
  const char *last = (s1 > s2) ? s1 : s2;
  return last ? std::string(path.c_str(), last - path.c_str() + 1) : "";
}
static std::string bytes_to_hex(const std::vector<uint8_t> &data) {
  static const char *hex = "0123456789ABCDEF";
  std::string result;
  result.reserve(data.size() * 2);
  for (uint8_t b : data) {
    result.push_back(hex[b >> 4]);
    result.push_back(hex[b & 0xF]);
  }
  return result;
}

// ===================== Footer 构建/解析 =====================
static std::vector<uint8_t>
build_footer(const std::vector<uint8_t> &enc_name, const Sha256Hash &name_hash,
             const std::array<uint8_t, 16> &salt, const AesIV &file_iv,
             const AesIV &name_iv, uint32_t tail_pad, uint32_t pre_pad) {
  std::vector<uint8_t> footer;
  footer.reserve(4 + 1 + 2 + enc_name.size() + 32 + 16 + 16 + 16 + 4 + 4);

  auto push_u32 = [&](uint32_t v) {
    footer.push_back((v >> 24) & 0xFF);
    footer.push_back((v >> 16) & 0xFF);
    footer.push_back((v >> 8) & 0xFF);
    footer.push_back(v & 0xFF);
  };
  auto push_u16 = [&](uint16_t v) {
    footer.push_back(v >> 8);
    footer.push_back(v & 0xFF);
  };

  push_u32(FOOTER_MAGIC);
  footer.push_back(3); // version
  push_u16(static_cast<uint16_t>(enc_name.size()));
  footer.insert(footer.end(), enc_name.begin(), enc_name.end());
  footer.insert(footer.end(), name_hash.begin(), name_hash.end());
  footer.insert(footer.end(), salt.begin(), salt.end());
  footer.insert(footer.end(), file_iv.begin(), file_iv.end());
  footer.insert(footer.end(), name_iv.begin(), name_iv.end());
  push_u32(tail_pad);
  push_u32(pre_pad);
  return footer;
}

static std::pair<bool, std::vector<uint8_t>> read_footer(FILE *file) {
  if (MPC_FSEEK(file, -4, SEEK_END) != 0)
    return {false, {}};
  uint8_t len_buf[4];
  if (fread(len_buf, 1, 4, file) != 4)
    return {false, {}};
  uint32_t footer_len = (uint32_t(len_buf[0]) << 24) |
                        (uint32_t(len_buf[1]) << 16) |
                        (uint32_t(len_buf[2]) << 8) | uint32_t(len_buf[3]);
  mpc_off_t start = -4 - static_cast<mpc_off_t>(footer_len);
  if (MPC_FSEEK(file, start, SEEK_END) != 0)
    return {false, {}};
  std::vector<uint8_t> footer(footer_len);
  if (fread(footer.data(), 1, footer_len, file) != footer_len)
    return {false, {}};
  return {true, std::move(footer)};
}

static bool parse_footer(const std::vector<uint8_t> &footer,
                         std::vector<uint8_t> &out_enc_name,
                         Sha256Hash &out_name_hash,
                         std::array<uint8_t, 16> &out_salt, AesIV &out_file_iv,
                         AesIV &out_name_iv, uint32_t &out_tail_pad,
                         uint32_t &out_pre_pad) {
  if (footer.size() < 4 + 1 + 2)
    return false;
  size_t pos = 0;
  uint32_t magic = (uint32_t(footer[pos]) << 24) |
                   (uint32_t(footer[pos + 1]) << 16) |
                   (uint32_t(footer[pos + 2]) << 8) | uint32_t(footer[pos + 3]);
  if (magic != FOOTER_MAGIC)
    return false;
  pos += 4;
  /*uint8_t ver =*/(void)footer[pos++];
  uint16_t name_len = (uint16_t(footer[pos]) << 8) | footer[pos + 1];
  pos += 2;
  if (pos + name_len + 32 + 16 + 16 + 16 > footer.size())
    return false;

  out_enc_name.assign(footer.begin() + pos, footer.begin() + pos + name_len);
  pos += name_len;
  std::copy(footer.begin() + pos, footer.begin() + pos + 32,
            out_name_hash.begin());
  pos += 32;
  std::copy(footer.begin() + pos, footer.begin() + pos + 16, out_salt.begin());
  pos += 16;
  std::copy(footer.begin() + pos, footer.begin() + pos + 16,
            out_file_iv.begin());
  pos += 16;
  std::copy(footer.begin() + pos, footer.begin() + pos + 16,
            out_name_iv.begin());
  pos += 16;

  out_tail_pad = out_pre_pad = 0;
  if (pos + 4 <= footer.size()) {
    out_tail_pad = (uint32_t(footer[pos]) << 24) |
                   (uint32_t(footer[pos + 1]) << 16) |
                   (uint32_t(footer[pos + 2]) << 8) | uint32_t(footer[pos + 3]);
    pos += 4;
  }
  if (pos + 4 <= footer.size()) {
    out_pre_pad = (uint32_t(footer[pos]) << 24) |
                  (uint32_t(footer[pos + 1]) << 16) |
                  (uint32_t(footer[pos + 2]) << 8) | uint32_t(footer[pos + 3]);
  }
  return true;
}

// ===================== 密钥派生 =====================
static AesKey derive_key(const char *password,
                         const std::array<uint8_t, 16> &salt) {
  std::vector<uint8_t> mat;
  mat.insert(mat.end(), password, password + strlen(password));
  mat.insert(mat.end(), salt.begin(), salt.end());
  auto hash = Sha256(mat.data(), mat.size());
  AesKey k;
  std::copy(hash.begin(), hash.end(), k.begin());
  return k;
}

// ===================== 带回调的加密实现 =====================
ErrorCode  encrypt_video_ex(const char *inputPath, const char *password,
                     const char *outputPath, ProgressCallback callback,
                     void *user_data) {
  if (!inputPath || !password)
    return ErrorCode::kInvalidParameter;
  FILE *in = mp_fopen(inputPath, "rb");
  if (!in)
    return ErrorCode::kInputFileOpenFailed;

  std::string orig_fn = extract_filename(inputPath);
  std::vector<uint8_t> orig_bytes(orig_fn.begin(), orig_fn.end());

  std::array<uint8_t, 16> salt{};
  AesIV file_iv{}, name_iv{};
  if (!fill_random(salt) || !fill_random(file_iv) || !fill_random(name_iv)) {
    fclose(in);
    return ErrorCode::kRandomFailed;
  }

  AesKey key = derive_key(password, salt);
  std::vector<uint8_t> enc_name = orig_bytes;
  AesCipher::Encrypt(enc_name, key, name_iv, AesMode::AES_CTR);
  auto name_hash = Sha256(orig_bytes.data(), orig_bytes.size());

std::string out_path;
if (outputPath && outputPath[0]) {
      constexpr size_t NAME_BYTES = 32;  // 32 字节 → 64 个十六进制字符
    size_t take = (std::min)(NAME_BYTES, enc_name.size());
    std::vector<uint8_t> partial_enc(enc_name.begin(), enc_name.begin() + take);
    out_path = extract_directory(outputPath) + bytes_to_hex(partial_enc);
} else {
    // 截取 enc_name 前 32 字节（若不足则全取），转十六进制作为文件名
    constexpr size_t NAME_BYTES = 32;  // 32 字节 → 64 个十六进制字符
    size_t take = (std::min)(NAME_BYTES, enc_name.size());
    std::vector<uint8_t> partial_enc(enc_name.begin(), enc_name.begin() + take);
    out_path = extract_directory(inputPath) + bytes_to_hex(partial_enc);
}

  FILE *out = mp_fopen(out_path.c_str(), "wb");
  if (!out) {
    fclose(in);
    return ErrorCode::kOutputFileOpenFailed;
  }

  // 获取原始文件大小
  MPC_FSEEK(in, 0, SEEK_END);
  mpc_off_t file_size = MPC_FTELL(in);
  MPC_FSEEK(in, 0, SEEK_SET);
  uint64_t total_original = static_cast<uint64_t>(file_size);
  uint64_t processed = 0;

  // 1. 开头随机填充
  uint32_t pre_pad = random_uint32_range(PADDING_MIN, PADDING_MAX);
  std::vector<uint8_t> pre_pad_bytes(pre_pad);
  if (!generate_random_bytes(pre_pad_bytes.data(), pre_pad))
    std::fill(pre_pad_bytes.begin(), pre_pad_bytes.end(), 0xAB);
  fwrite(pre_pad_bytes.data(), 1, pre_pad, out);

  // 2. 加密头部（4MB）
  size_t head_len = static_cast<size_t>(
      (std::min)(static_cast<mpc_off_t>(HEAD_ENCRYPT_SIZE), file_size));
  std::vector<uint8_t> head(head_len);
  if (fread(head.data(), 1, head_len, in) != head_len) {
    fclose(in);
    fclose(out);
    return ErrorCode::kReadWriteFailed; // 读写错误
  }
  AesCipher::Encrypt(head, key, file_iv, AesMode::AES_CTR);
  fwrite(head.data(), 1, head.size(), out);
  processed += head_len;

  // 第一次进度回调（头部处理完）
  if (callback)
    callback(processed, total_original, user_data);

  // 3. 复制剩余原始数据
  mpc_off_t remaining = file_size - static_cast<mpc_off_t>(head_len);
  if (remaining > 0) {
    std::vector<uint8_t> buf(64 * 1024);
    uint64_t last_cb = processed;
    constexpr uint64_t MIN_INTERVAL = 1024 * 1024; // 1 MB
    uint64_t cb_interval = (std::max)(MIN_INTERVAL, total_original / 100);
    while (remaining > 0) {
      size_t to_read = static_cast<size_t>(
          (std::min)(static_cast<mpc_off_t>(buf.size()), remaining));
      if (fread(buf.data(), 1, to_read, in) != to_read) {
        fclose(in);
        fclose(out);
        return ErrorCode::kReadWriteFailed;
      }
      fwrite(buf.data(), 1, to_read, out);
      remaining -= to_read;
      processed += to_read;
      if (callback && (processed - last_cb >= cb_interval || remaining == 0)) {
        callback(processed, total_original, user_data);
        last_cb = processed;
      }
    }
  }
  fclose(in);

  // 4. 尾部随机填充
  uint32_t tail_pad = random_uint32_range(PADDING_MIN, PADDING_MAX);
  std::vector<uint8_t> tail_pad_bytes(tail_pad);
  if (!generate_random_bytes(tail_pad_bytes.data(), tail_pad))
    std::fill(tail_pad_bytes.begin(), tail_pad_bytes.end(), 0xCD);
  fwrite(tail_pad_bytes.data(), 1, tail_pad, out);

  // 5. Footer + 长度
  auto footer = build_footer(enc_name, name_hash, salt, file_iv, name_iv,
                             tail_pad, pre_pad);
  fwrite(footer.data(), 1, footer.size(), out);
  uint32_t flen = static_cast<uint32_t>(footer.size());
  uint8_t flen_buf[4] = {uint8_t(flen >> 24), uint8_t(flen >> 16),
                         uint8_t(flen >> 8), uint8_t(flen)};
  fwrite(flen_buf, 1, 4, out);
  fclose(out);

  // 最终回调确保 100%
  if (callback)
    callback(total_original, total_original, user_data);
  return ErrorCode::kSuccess;
}

// ===================== 带回调的解密实现 =====================
ErrorCode  decrypt_video_ex(const char *inputPath, const char *password,
                     const char *outputPath, ProgressCallback callback,
                     void *user_data) {
  if (!inputPath || !password)
    return ErrorCode::kInvalidParameter;
  FILE *in = mp_fopen(inputPath, "rb");
  if (!in)
    return ErrorCode::kInputFileOpenFailed;

  MPC_FSEEK(in, 0, SEEK_END);
  mpc_off_t total_size = MPC_FTELL(in);
  if (total_size < 91) {
    fclose(in);
    return ErrorCode::kFooterInvalid ;
  }

  auto [ok, footer_data] = read_footer(in);
  if (!ok) {
    fclose(in);
    return ErrorCode::kFooterInvalid ;
  }

  std::vector<uint8_t> enc_name;
  Sha256Hash name_hash;
  std::array<uint8_t, 16> salt;
  AesIV file_iv, name_iv;
  uint32_t tail_pad = 0, pre_pad = 0;
  if (!parse_footer(footer_data, enc_name, name_hash, salt, file_iv, name_iv,
                    tail_pad, pre_pad)) {
    fclose(in);
    return ErrorCode::kFooterInvalid ;
  }

  AesKey key = derive_key(password, salt);
  std::vector<uint8_t> dec_name = enc_name;
  AesCipher::Decrypt(dec_name, key, name_iv, AesMode::AES_CTR);
  auto calc_hash = Sha256(dec_name.data(), dec_name.size());
  if (!std::equal(name_hash.begin(), name_hash.end(), calc_hash.begin())) {
    fclose(in);
    return ErrorCode::kWrongPassword;
  }

  std::string orig_fn(dec_name.begin(), dec_name.end());
  std::string out_path;
  if (outputPath && outputPath[0])
    out_path = extract_directory(outputPath) + orig_fn;
  else
    out_path = extract_directory(inputPath) + orig_fn;

  FILE *out = mp_fopen(out_path.c_str(), "wb");
  if (!out) {
    fclose(in);
    return ErrorCode::kOutputFileOpenFailed;
  }

  // 计算有效视频数据长度
  mpc_off_t video_len =
      total_size - 4 - static_cast<mpc_off_t>(footer_data.size()) -
      static_cast<mpc_off_t>(tail_pad) - static_cast<mpc_off_t>(pre_pad);
  if (video_len < 0 || video_len > total_size) {
    fclose(in);
    fclose(out);
    return ErrorCode::kFileSizeInvalid;
  }
  uint64_t total_video = static_cast<uint64_t>(video_len);
  uint64_t processed = 0;

  // 跳过开头填充
  if (MPC_FSEEK(in, static_cast<mpc_off_t>(pre_pad), SEEK_SET) != 0) {
    fclose(in);
    fclose(out);
    return ErrorCode::kSeekFailed;
  }

  // 解密头部
  size_t head_len = static_cast<size_t>(
      (std::min)(static_cast<mpc_off_t>(HEAD_ENCRYPT_SIZE), video_len));
  std::vector<uint8_t> head(head_len);
  if (fread(head.data(), 1, head_len, in) != head_len) {
    fclose(in);
    fclose(out);
    return ErrorCode::kReadWriteFailed; // 读写错误
  }
  AesCipher::Decrypt(head, key, file_iv, AesMode::AES_CTR);
  if (fwrite(head.data(), 1, head.size(), out) != head.size()) {
    fclose(in);
    fclose(out);
    return ErrorCode::kReadWriteFailed;
  }
  processed += head_len;
  if (callback)
    callback(processed, total_video, user_data);

  // 复制剩余
  mpc_off_t remaining = video_len - static_cast<mpc_off_t>(head_len);
  std::vector<uint8_t> buf(64 * 1024);
  uint64_t last_cb = processed;
  constexpr uint64_t MIN_INTERVAL = 1024 * 1024; // 1 MB
  uint64_t cb_interval = (std::max)(MIN_INTERVAL, total_video / 100);
  while (remaining > 0) {

size_t to_read = static_cast<size_t>((std::min)(static_cast<mpc_off_t>(buf.size()), remaining));
    if (fread(buf.data(), 1, to_read, in) != to_read) {
      fclose(in);
      fclose(out);
      return ErrorCode::kReadWriteFailed;
    }
    if (fwrite(buf.data(), 1, to_read, out) != to_read) {
      fclose(in);
      fclose(out);
      return ErrorCode::kReadWriteFailed;
    }
    remaining -= to_read;
    processed += to_read;
    if (callback && (processed - last_cb >= cb_interval || remaining == 0)) {
      callback(processed, total_video, user_data);
      last_cb = processed;
    }
  }

  fclose(in);
  fclose(out);
  if (callback)
    callback(total_video, total_video, user_data);
  return ErrorCode::kSuccess;
}

// ===================== 无回调的旧接口（转发） =====================
ErrorCode  encrypt_video(const char *inputPath, const char *password,
                  const char *outputPath) {
  return encrypt_video_ex(inputPath, password, outputPath, nullptr, nullptr);
}

ErrorCode  decrypt_video(const char *inputPath, const char *password,
                  const char *outputPath) {
  return decrypt_video_ex(inputPath, password, outputPath, nullptr, nullptr);
}

} // namespace mpcrypt
