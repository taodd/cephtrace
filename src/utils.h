#ifndef UTILS_H
#define UTILS_H

#include <string>

// Extract basename from a file path (e.g., "/usr/bin/ceph-osd" -> "ceph-osd")
inline std::string get_basename(const std::string& path) {
    size_t pos = path.find_last_of('/');
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

#endif // UTILS_H

