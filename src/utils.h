#ifndef UTILS_H
#define UTILS_H

#include <algorithm>
#include <cctype>
#include <cstdint>
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

// Size BPF_MAP_TYPE_LRU_HASH maps (ops, ptid_opk, ctx_opk) for the host CPU
// count.  Linux's bpf_lru_list maintains per-CPU free lists targeting
// LOCAL_FREE_TARGET (128) entries per CPU, so an 8192-entry map can spend its
// entire pool on per-CPU caches at 64 CPUs and evict live in-flight ops before
// stealing idle free nodes from other CPUs.  256 entries per possible CPU keeps
// at least half the pool available to the global LRU lists while capping memory
// on systems with large hotplug possible-CPU masks.
inline uint32_t calc_osd_lru_map_entries(int ncpus) {
    constexpr uint64_t MIN_LRU_ENTRIES = 8192;
    constexpr uint64_t ENTRIES_PER_CPU = 256;
    constexpr uint64_t MAX_LRU_ENTRIES = 262144;
    if (ncpus <= 0)
        return static_cast<uint32_t>(MIN_LRU_ENTRIES);
    uint64_t scaled = static_cast<uint64_t>(ncpus) * ENTRIES_PER_CPU;
    return static_cast<uint32_t>(
        std::min(MAX_LRU_ENTRIES, std::max(MIN_LRU_ENTRIES, scaled)));
}

#endif // UTILS_H

