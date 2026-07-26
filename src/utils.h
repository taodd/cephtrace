#ifndef UTILS_H
#define UTILS_H

#include <cctype>
#include <string>
#include <unistd.h>
#include <vector>

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

// Extract OSD ID from a list of command-line argument tokens.
// Handles formats: --id <id>, --id=<id>, -i <id>, -i<id>, -n osd.<id>, --name osd.<id>, --name=osd.<id>
inline int parse_osd_id_from_tokens(const std::vector<std::string> &args) {
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string &arg = args[i];

        // Case 1: --id 0 or -i 0
        if ((arg == "--id" || arg == "-i") && i + 1 < args.size()) {
            try { return std::stoi(args[i + 1]); } catch (...) {}
        }
        // Case 2: --id=0
        if (arg.rfind("--id=", 0) == 0) {
            try { return std::stoi(arg.substr(5)); } catch (...) {}
        }
        // Case 3: -i12 (no space)
        if (arg.size() > 2 && arg.rfind("-i", 0) == 0 && std::isdigit(static_cast<unsigned char>(arg[2]))) {
            try { return std::stoi(arg.substr(2)); } catch (...) {}
        }
        // Case 4: -n osd.0 or --name osd.0
        if ((arg == "-n" || arg == "--name") && i + 1 < args.size()) {
            if (args[i + 1].rfind("osd.", 0) == 0) {
                try { return std::stoi(args[i + 1].substr(4)); } catch (...) {}
            }
        }
        // Case 5: --name=osd.0
        if (arg.rfind("--name=osd.", 0) == 0) {
            try { return std::stoi(arg.substr(11)); } catch (...) {}
        }
    }
    return -1;
}

#endif // UTILS_H

