#include "utils.h"
#include "exceptions.h"

#include <nettle/aes.h>
#include <nettle/gcm.h>
#include <nettle/hmac.h>
#include <nettle/sha.h>
#include <nettle/yarrow.h>

#include <algorithm>
#include <mutex>
#include <string.h>
#include <time.h>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

namespace securefs
{

/*
 Formatting library for C++

 Copyright (c) 2012 - 2015, Victor Zverovich
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Portable thread-safe version of strerror.
// Sets buffer to point to a string describing the error code.
// This can be either a pointer to a string stored in buffer,
// or a pointer to some static immutable string.
// Returns one of the following values:
//   0      - success
//   ERANGE - buffer is not large enough to store the error message
//   other  - failure
// Buffer should be at least of size 1.
static int safe_strerror(int error_code, char*& buffer, size_t buffer_size) noexcept
{
    assert(buffer != 0 && buffer_size != 0);
    int result = 0;
#if ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE) || __ANDROID__
    // XSI-compliant version of strerror_r.
    result = strerror_r(error_code, buffer, buffer_size);
    if (result != 0)
        result = errno;
#elif _GNU_SOURCE
    // GNU-specific version of strerror_r.
    char* message = strerror_r(error_code, buffer, buffer_size);
    // If the buffer is full then the message is probably truncated.
    if (message == buffer && strlen(buffer) == buffer_size - 1)
        result = ERANGE;
    buffer = message;
#elif __MINGW32__
    errno = 0;
    (void)buffer_size;
    buffer = strerror(error_code);
    result = errno;
#elif _WIN32
    result = strerror_s(buffer, buffer_size, error_code);
    // If the buffer is full then the message is probably truncated.
    if (result == 0 && std::strlen(buffer) == buffer_size - 1)
        result = ERANGE;
#else
    result = strerror_r(error_code, buffer, buffer_size);
    if (result == -1)
        result = errno;    // glibc versions before 2.13 return result in errno.
#endif
    return result;
}

std::string sane_strerror(int error_number)
{
    char buffer[4096];
    char* output = buffer;
    int rc = safe_strerror(error_number, output, sizeof(buffer));
    if (rc == 0)
        return std::string(output);
    return fmt::format("Unknown error with code {}", error_number);
}

void parse_hex(const std::string& hex, byte* output, size_t len)
{
    if (hex.size() % 2 != 0)
        throw InvalidArgumentException("Hex string must have an even length");
    if (hex.size() / 2 != len)
        throw InvalidArgumentException("Mismatch hex and raw length");

    for (size_t i = 0; i < hex.size(); i += 2, ++output)
    {
        switch (hex[i])
        {
        case '0':
            *output = 0x0;
            break;
        case '1':
            *output = 0x10;
            break;
        case '2':
            *output = 0x20;
            break;
        case '3':
            *output = 0x30;
            break;
        case '4':
            *output = 0x40;
            break;
        case '5':
            *output = 0x50;
            break;
        case '6':
            *output = 0x60;
            break;
        case '7':
            *output = 0x70;
            break;
        case '8':
            *output = 0x80;
            break;
        case '9':
            *output = 0x90;
            break;
        case 'a':
            *output = 0xa0;
            break;
        case 'b':
            *output = 0xb0;
            break;
        case 'c':
            *output = 0xc0;
            break;
        case 'd':
            *output = 0xd0;
            break;
        case 'e':
            *output = 0xe0;
            break;
        case 'f':
            *output = 0xf0;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
        switch (hex[i + 1])
        {
        case '0':
            *output += 0x0;
            break;
        case '1':
            *output += 0x1;
            break;
        case '2':
            *output += 0x2;
            break;
        case '3':
            *output += 0x3;
            break;
        case '4':
            *output += 0x4;
            break;
        case '5':
            *output += 0x5;
            break;
        case '6':
            *output += 0x6;
            break;
        case '7':
            *output += 0x7;
            break;
        case '8':
            *output += 0x8;
            break;
        case '9':
            *output += 0x9;
            break;
        case 'a':
            *output += 0xa;
            break;
        case 'b':
            *output += 0xb;
            break;
        case 'c':
            *output += 0xc;
            break;
        case 'd':
            *output += 0xd;
            break;
        case 'e':
            *output += 0xe;
            break;
        case 'f':
            *output += 0xf;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
    }
}

void aes_gcm_encrypt(const byte* plaintext,
                     size_t text_len,
                     const byte* header,
                     size_t header_len,
                     const byte* key,
                     size_t key_len,
                     const byte* iv,
                     size_t iv_len,
                     byte* mac,
                     size_t mac_len,
                     byte* ciphertext)
{
    if (key_len != AES256_KEY_SIZE)
        throw InvalidArgumentException("Invalid key size");

    gcm_aes256_ctx ctx;
    nettle_gcm_aes256_set_key(&ctx, key);
    nettle_gcm_aes256_set_iv(&ctx, iv_len, iv);

    while (header_len >= AES_BLOCK_SIZE)
    {
        nettle_gcm_aes256_update(&ctx, AES_BLOCK_SIZE, header);
        header += AES_BLOCK_SIZE;
        header_len -= AES_BLOCK_SIZE;
    }
    if (header_len > 0)
        nettle_gcm_aes256_update(&ctx, header_len, header);

    while (text_len >= AES_BLOCK_SIZE)
    {
        nettle_gcm_aes256_encrypt(&ctx, AES_BLOCK_SIZE, ciphertext, plaintext);
        plaintext += AES_BLOCK_SIZE;
        ciphertext += AES_BLOCK_SIZE;
        text_len -= AES_BLOCK_SIZE;
    }
    if (text_len > 0)
    {
        nettle_gcm_aes256_encrypt(&ctx, text_len, ciphertext, plaintext);
    }
    nettle_gcm_aes256_digest(&ctx, mac_len, mac);
}

bool aes_gcm_decrypt(const byte* ciphertext,
                     size_t text_len,
                     const byte* header,
                     size_t header_len,
                     const byte* key,
                     size_t key_len,
                     const byte* iv,
                     size_t iv_len,
                     const byte* mac,
                     size_t mac_len,
                     byte* plaintext)
{
    if (key_len != AES256_KEY_SIZE)
        throw InvalidArgumentException("Invalid key size");

    gcm_aes256_ctx ctx;
    nettle_gcm_aes256_set_key(&ctx, key);
    nettle_gcm_aes256_set_iv(&ctx, iv_len, iv);

    while (header_len >= AES_BLOCK_SIZE)
    {
        nettle_gcm_aes256_update(&ctx, AES_BLOCK_SIZE, header);
        header += AES_BLOCK_SIZE;
        header_len -= AES_BLOCK_SIZE;
    }
    if (header_len > 0)
        nettle_gcm_aes256_update(&ctx, header_len, header);

    while (text_len >= AES_BLOCK_SIZE)
    {
        nettle_gcm_aes256_decrypt(&ctx, AES_BLOCK_SIZE, plaintext, ciphertext);
        plaintext += AES_BLOCK_SIZE;
        ciphertext += AES_BLOCK_SIZE;
        text_len -= AES_BLOCK_SIZE;
    }
    if (text_len > 0)
    {
        nettle_gcm_aes256_decrypt(&ctx, text_len, plaintext, ciphertext);
    }
    std::array<byte, GCM_DIGEST_SIZE> digest;
    nettle_gcm_aes256_digest(&ctx, digest.size(), digest.data());
    return constant_time_compare(mac,
                                 digest.data(),
                                 std::min(digest.size(), mac_len),
                                 std::min(digest.size(), mac_len))
        == 0;
}

void generate_random(byte* data, size_t size)
{
    static std::mutex lock;
    static int fd = -1;

    std::lock_guard<std::mutex> guard(lock);
    if (fd < 0)
    {
        fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0)
            throw UnderlyingOSException(errno, "/dev/urandom failure");
    }
    if (::read(fd, data, size) != static_cast<ssize_t>(size))
        throw UnderlyingOSException(errno, "Reading from /dev/urandom fails");
}

static void hkdf_expand(const byte* distilled_key,
                        size_t dis_len,
                        const byte* info,
                        size_t info_len,
                        byte* out,
                        size_t out_len)
{

    if (out_len > 255 * SHA256_DIGEST_SIZE)
        throw InvalidArgumentException("Output length too large");
    hmac_sha256_ctx ctx;
    nettle_hmac_sha256_set_key(&ctx, dis_len, distilled_key);

    size_t i = 0, j = 0;
    byte counter = 1;
    while (i + j < out_len)
    {
        nettle_hmac_sha256_update(&ctx, j, out + i);
        if (info_len > 0)
            nettle_hmac_sha256_update(&ctx, info_len, info);
        nettle_hmac_sha256_update(&ctx, sizeof(counter), &counter);
        ++counter;

        auto left_size = out_len - i - j;
        i += j;
        if (left_size >= SHA256_DIGEST_SIZE)
        {
            nettle_hmac_sha256_digest(&ctx, SHA256_DIGEST_SIZE, out + i);
            j = SHA256_DIGEST_SIZE;
        }
        else
        {
            std::array<byte, SHA256_DIGEST_SIZE> buffer;
            nettle_hmac_sha256_digest(&ctx, buffer.size(), buffer.data());
            memcpy(out + i, buffer.data(), left_size);
            j = left_size;
        }
    }
}

void hkdf(const byte* key,
          size_t key_len,
          const byte* salt,
          size_t salt_len,
          const byte* info,
          size_t info_len,
          byte* output,
          size_t out_len)
{
    if (salt && salt_len)
    {
        std::array<byte, SHA256_DIGEST_SIZE> distilled_key;
        hmac_sha256_ctx ctx;
        nettle_hmac_sha256_set_key(&ctx, salt_len, salt);
        nettle_hmac_sha256_update(&ctx, key_len, key);
        nettle_hmac_sha256_digest(&ctx, distilled_key.size(), distilled_key.data());
        hkdf_expand(distilled_key.data(), distilled_key.size(), info, info_len, output, out_len);
    }
    else
    {
        hkdf_expand(key, key_len, info, info_len, output, out_len);
    }
}

size_t insecure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
    if (!fp || !password)
        NULL_EXCEPT();

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    size_t actual_read = 0;
    auto output = static_cast<unsigned char*>(password);

    while (actual_read < max_length)
    {
        int ch = fgetc(fp);
        if (ch == EOF)
        {
            if (feof(fp))
                break;
            if (ferror(fp))
                throw OSException(errno);
        }
        if (ch == '\0' || ch == '\n' || ch == '\r')
            break;
        *output = static_cast<unsigned char>(ch);
        ++output;
        ++actual_read;
    }

    if (actual_read >= max_length)
        fprintf(stderr,
                "Warning: password is longer than %llu and therefore truncated\n",
                static_cast<unsigned long long>(max_length));
    return actual_read;
}

size_t secure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
    if (!fp || !password)
        NULL_EXCEPT();

    int fd = fileno(fp);
    struct termios old_termios, new_termios;
    int rc = ::tcgetattr(fd, &old_termios);
    if (rc < 0)
        throw OSException(errno);
    if (!(old_termios.c_lflag & ECHO))
        throw InvalidArgumentException("Unechoed terminal");

    memcpy(&new_termios, &old_termios, sizeof(old_termios));
    new_termios.c_lflag &= ~ECHO;
    new_termios.c_lflag |= ECHONL;
    rc = ::tcsetattr(fd, TCSAFLUSH, &new_termios);
    if (rc < 0)
        throw OSException(errno);
    auto retval = insecure_read_password(fp, prompt, password, max_length);
    (void)::tcsetattr(fd, TCSAFLUSH, &old_termios);
    return retval;
}

std::string format_current_time()
{
    struct timeval now;
    (void)gettimeofday(&now, nullptr);
    struct tm tm;
    gmtime_r(&now.tv_sec, &tm);
    return fmt::format("{}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:06d}Z",
                       tm.tm_year + 1900,
                       tm.tm_mon + 1,
                       tm.tm_mday,
                       tm.tm_hour,
                       tm.tm_min,
                       tm.tm_sec,
                       now.tv_usec);
}

void ensure_directory(int base_fd, const char* dir_name, mode_t mode)
{
    int rc = ::mkdirat(base_fd, dir_name, mode);
    if (rc < 0 && errno != EEXIST)
        throw securefs::OSException(errno);
}

std::vector<std::string> split(const char* str, size_t length, char separator)
{
    const char* end = str + length;
    const char* start = str;
    std::vector<std::string> result;

    while (str < end)
    {
        if (*str == separator)
        {
            if (start < str)
                result.emplace_back(start, str);
            start = str + 1;
        }
        ++str;
    }

    if (start < end)
        result.emplace_back(start, end);
    return result;
}

static void find_ids_helper(const std::string& current_dir,
                            std::unordered_set<id_type, id_hash>& result)
{
    struct DirGuard
    {
        DIR* dp = nullptr;

        DirGuard() {}
        ~DirGuard() { ::closedir(dp); }
    };

    DIR* dp = ::opendir(current_dir.c_str());
    if (!dp)
    {
        if (errno == ENOTDIR)
            return;
        throw UnderlyingOSException(errno, fmt::format("Opening dir {}", current_dir));
    }

    DirGuard guard;
    guard.dp = dp;
    id_type id;
    std::string hex(id_type::size() * 2, 0);

    while (true)
    {
        errno = 0;
        dirent* dr = ::readdir(dp);
        if (!dr && errno)
            throw UnderlyingOSException(errno, fmt::format("Reading dir {}", current_dir));
        if (!dr)
            break;
        std::string name(dr->d_name);
        if (name == "." || name == "..")
            continue;
        if (dr->d_type == DT_REG && ends_with(name.data(), name.size(), ".meta", strlen(".meta")))
        {
            std::string total_name
                = current_dir + '/' + name.substr(0, name.size() - strlen(".meta"));
            hex.assign(hex.size(), 0);
            ptrdiff_t i = hex.size() - 1, j = total_name.size() - 1;
            while (i >= 0 && j >= 0)
            {
                char namechar = total_name[j];
                if ((namechar >= '0' && namechar <= '9') || (namechar >= 'a' && namechar <= 'f'))
                {
                    hex[i] = namechar;
                    --i;
                }
                else if (namechar != '/')
                {
                    throw std::runtime_error(
                        fmt::format("File \"{}\" has extension .meta, but not a valid securefs "
                                    "meta filename. Please cleanup the underlying storage first.",
                                    total_name));
                }
                --j;
            }
            parse_hex(hex, id.data(), id.size());
            result.insert(id);
        }
        else if (dr->d_type == DT_DIR)
        {
            find_ids_helper(current_dir + '/' + name, result);
        }
    }
}

std::unordered_set<id_type, id_hash> find_all_ids(const std::string& basedir)
{
    std::unordered_set<id_type, id_hash> result;
    find_ids_helper(basedir, result);
    return result;
}

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len)
{
    return size >= suffix_len && memcmp(str + size - suffix_len, suffix, suffix_len) == 0;
}

std::string get_user_input_until_enter()
{
    std::string result;
    while (true)
    {
        int ch = getchar();
        if (ch == EOF)
        {
            return result;
        }
        if (ch == '\r' || ch == '\n')
        {
            while (!result.empty() && isspace(static_cast<unsigned char>(result.back())))
                result.pop_back();
            result.push_back('\n');
            return result;
        }
        else if (!result.empty() || !isspace(ch))
        {
            result.push_back(static_cast<unsigned char>(ch));
        }
    }
    return result;
}

void respond_to_user_action(
    const std::unordered_map<std::string, std::function<void(void)>>& actionMap)
{
    while (true)
    {
        std::string cmd = get_user_input_until_enter();
        if (cmd.empty() || cmd.back() != '\n')
        {
            // EOF
            return;
        }
        auto it = actionMap.find(cmd);
        if (it == actionMap.end())
        {
            puts("Invalid command");
            continue;
        }
        it->second();
        break;
    }
}

int constant_time_compare(const byte* a, const byte* b, size_t a_size, size_t b_size)
{
    if (a_size > b_size)
        return 1;
    if (a_size < b_size)
        return -1;

    int rc = 0;
    for (size_t i = 0; i < a_size; ++i)
        rc |= a[i] ^ b[i];
    return rc;
}

SecureByteBlock::SecureByteBlock(size_t size)
{
    m_size = size;
    m_data = static_cast<char*>(std::calloc(1, size));
    if (!m_data)
        throw std::bad_alloc();
}

static void __attribute__((optnone)) erase_and_free(void* buffer, size_t size)
{
    std::memset(buffer, 0xff, size);
    std::free(buffer);
}

SecureByteBlock::~SecureByteBlock() { erase_and_free(m_data, m_size); }
}
