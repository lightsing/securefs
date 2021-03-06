#include "mystring.h"
#include "exceptions.h"

#include <system_error>

namespace securefs
{
std::string vstrprintf(const char* format, va_list args)
{
    va_list copied_args;
    va_copy(copied_args, args);
    const int MAX_SIZE = 499;
    char buffer[MAX_SIZE + 1];
    int size = vsnprintf(buffer, sizeof(buffer), format, copied_args);
    va_end(copied_args);
    if (size < 0)
        throw POSIXException(errno, "vsnprintf");
    if (size <= MAX_SIZE)
        return std::string(buffer, size);
    std::string result(static_cast<std::string::size_type>(size), '\0');
    vsnprintf(&result[0], size + 1, format, args);
    return result;
}

std::string strprintf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    try
    {
        auto result = vstrprintf(format, args);
        va_end(args);
        return result;
    }
    catch (...)
    {
        va_end(args);
        throw;
    }
}

std::string to_lower(const std::string& str)
{
    std::string result = str;
    for (char& c : result)
    {
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    }
    return result;
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

std::string sane_strerror(int error_number) { return std::system_category().message(error_number); }

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len)
{
    return size >= suffix_len && memcmp(str + size - suffix_len, suffix, suffix_len) == 0;
}

bool starts_with(const char* str, size_t size, const char* prefix, size_t prefix_len)
{
    return size >= prefix_len && memcmp(str, prefix, prefix_len) == 0;
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

std::string hexify(const byte* data, size_t length)
{
    const char* table = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        result += table[data[i] / 16];
        result += table[data[i] % 16];
    }
    return result;
}
}