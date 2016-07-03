#pragma once

#include "file_table.h"
#include "myutils.h"

namespace securefs
{
namespace vfs
{
    AutoClosedFileBase
    open_base_dir(FileTable* table, const char* path, std::string* last_component);

    AutoClosedFileBase open_all(FileTable* table, const char* path);

    void remove(FileTable* table, const char* path);

    void create_file(FileTable* table, const char* path);

    void create_directory(FileTable* table, const char* path);

    void rename(FileTable* table, const char* src, const char* dest);

    void link(FileTable* table, const char* src, const char* dest);

    void symlink(FileTable* table, const char* src, const char* dest);
}
}