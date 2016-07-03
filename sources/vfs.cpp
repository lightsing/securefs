#include "vfs.h"

namespace securefs
{
namespace vfs
{
    static const id_type null_id{};

    AutoClosedFileBase
    open_base_dir(FileTable* table, const char* path, std::string* last_component)
    {
        auto components = split(path, '/');
        auto dir = open_as(*table, null_id, FileBase::DIRECTORY);
        if (components.empty())
        {
            if (last_component)
                last_component->clear();
            return dir;
        }
        id_type id;
        int type;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            bool exists = dir.get_as<Directory>()->get_entry(components[i], id, type);
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            open_as(*table, id, type).swap(dir);
        }
        if (last_component)
            last_component->swap(components.back());
        return dir;
    }

    AutoClosedFileBase open_all(FileTable* table, const char* path)
    {
        std::string last_component;
        auto dir = open_base_dir(table, path, &last_component);
        if (last_component.empty())
            return dir;
        id_type id;
        int type;
        bool exists = dir.get_as<Directory>()->get_entry(last_component, id, type);
        if (!exists)
            throw OSException(ENOENT);
        return open_as(*table, id, type);
    }

    void remove(FileTable* table, const char* path)
    {
        std::string last_component;
        auto dir_guard = open_base_dir(table, path, &last_component);
        auto dir = dir_guard.get_as<Directory>();
        if (last_component.empty())
            throw OSException(EPERM); // Cannot remove the root directory
        id_type id;
        int type;

        if (!dir->get_entry(last_component, id, type))
            throw OSException(ENOENT);

        auto inner_guard = open_as(*table, id, type);
        auto inner_fb = inner_guard.get();
        if (inner_fb->type() == FileBase::DIRECTORY && !static_cast<Directory*>(inner_fb)->empty())
            throw OSException(ENOTEMPTY);
        dir->remove_entry(last_component, id, type);
        inner_fb->unlink();
    }

    void create_file(FileTable* table, const char* path);

    void create_directory(FileTable* table, const char* path);

    void rename(FileTable* table, const char* src, const char* dest);

    void link(FileTable* table, const char* src, const char* dest);

    void symlink(FileTable* table, const char* src, const char* dest);
}
}