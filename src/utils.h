#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <unistd.h>

// Extract basename from a file path (e.g., "/usr/bin/ceph-osd" -> "ceph-osd")
inline std::string get_basename(const std::string& path) {
    size_t pos = path.find_last_of('/');
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

// Read the executable path for a process from /proc/<pid>/exe.
// Strips the " (deleted)" suffix if present.
// Returns an empty string on failure.
inline std::string get_exe_path_for_pid(int pid) {
    std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
    char exe_path[4096];
    ssize_t len = readlink(exe_link.c_str(), exe_path, sizeof(exe_path) - 1);
    if (len == -1)
        return "";
    exe_path[len] = '\0';
    std::string target(exe_path);
    size_t deleted_pos = target.find(" (deleted)");
    if (deleted_pos != std::string::npos)
        target = target.substr(0, deleted_pos);
    return target;
}

#endif // UTILS_H

