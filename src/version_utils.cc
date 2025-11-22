#include "version_utils.h"
#include <iostream>
#include <fstream>
#include <dirent.h>
#include <ctype.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <vector>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

std::string get_package_version(const std::string& library_path) {
    // Extract the library name from the path
    std::string lib_name;
    size_t last_slash = library_path.find_last_of('/');
    if (last_slash != std::string::npos) {
        lib_name = library_path.substr(last_slash + 1);
    } else {
        lib_name = library_path;
    }

    // Remove .so extension and version numbers
    std::string base_name = lib_name;
    size_t dot_pos = base_name.find(".so");
    if (dot_pos != std::string::npos) {
        base_name = base_name.substr(0, dot_pos);
    }

    // Remove "lib" prefix if present
    if (base_name.substr(0, 3) == "lib") {
        base_name = base_name.substr(3);
    }

    // Determine alternative package names for Ceph libraries
    std::vector<std::string> alt_names;
    if (base_name == "rados") {
        alt_names = {"librados2", "ceph-common"};
    } else if (base_name == "rbd") {
        alt_names = {"librbd1", "ceph-common"};
    } else if (base_name == "ceph-common") {
        alt_names = {"ceph-common"};
    } else if (base_name == "ceph-osd") {
        alt_names = {"ceph-osd", "ceph-common"};
    } else {
        alt_names = {base_name};
    }

    char buffer[256];
    std::string result = "";

    // Detect which package manager is available
    bool has_dpkg = (access("/usr/bin/dpkg", X_OK) == 0);
    bool has_rpm = (access("/usr/bin/rpm", X_OK) == 0);

    // Try dpkg first (Debian/Ubuntu)
    if (has_dpkg) {
        for (const auto& pkg_name : alt_names) {
            std::string cmd = "dpkg -s " + pkg_name + " 2>/dev/null | grep '^Version:' | cut -d' ' -f2";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                result = "";
                while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                    result += buffer;
                }
                pclose(pipe);

                if (!result.empty() && result[result.length()-1] == '\n') {
                    result.erase(result.length()-1);
                }

                if (!result.empty()) {
                    return result;
                }
            }
        }
    }

    // Try rpm (CentOS/RHEL/Rocky)
    if (has_rpm && result.empty()) {
        for (const auto& pkg_name : alt_names) {
            std::string cmd = "rpm -q " + pkg_name + " --queryformat '%{EPOCH}:%{VERSION}-%{RELEASE}' 2>/dev/null";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                result = "";
                while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                    result += buffer;
                }
                pclose(pipe);

                if (!result.empty() && result[result.length()-1] == '\n') {
                    result.erase(result.length()-1);
                }

                // Check if the package is not installed (rpm returns "package X is not installed")
                if (!result.empty() && result.find("not installed") == std::string::npos) {
                    return result;
                }
                result = "";
            }
        }
    }

    return result.empty() ? "unknown" : result;
}

bool check_process_library_deleted(int pid, const std::string& lib_name) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        std::cerr << "Error: Could not open " << maps_path << " for process " << pid << std::endl;
        return true;
    }
    
    std::string line;
    bool is_deleted = false;
    
    // Look for the library in the process memory maps
    while (std::getline(maps_file, line)) {
        // Parse the maps line to extract the library path
        // Format: start-end perms offset dev inode path
        if (line.find(lib_name) != std::string::npos) {
            // Check if the library is marked as deleted (old version still in memory)
            if (line.find("(deleted)") != std::string::npos) {
                is_deleted = true;
                std::cerr << lib_name << " is deleted in process " << pid << std::endl;
                break;
            }
        }
    }
    
    maps_file.close();
    return is_deleted;
}

// Check if the library is updated on disk and old version is still in use
bool check_library_deleted(int process_id, const std::string& lib_name) {
    
    if (process_id > 0) {
        // Check specific process
        bool found_deleted = check_process_library_deleted(process_id, lib_name);
        if (found_deleted) {
            return true;
        }
    } else {
        // Check all processes using lib_name
        std::vector<int> pids;
        
        // Find all processes that have lib_name loaded
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            std::cerr << "Error: Could not open /proc directory" << std::endl;
            return true;
        }
        
        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            // Check if it's a numeric directory (process ID)
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                int pid = std::stoi(entry->d_name);
                std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
                std::ifstream maps_file(maps_path);
                
                if (maps_file.is_open()) {
                    std::string line;
                    bool has_lib = false;
                    
                    while (std::getline(maps_file, line)) {
                        if (line.find(lib_name) != std::string::npos) {
                            has_lib = true;
                            break;
                        }
                    }
                    
                    if (has_lib) {
                        pids.push_back(pid);
                    }
                    
                    maps_file.close();
                }
            }
        }
        closedir(proc_dir);
        
        // Check if any process is using deleted library 
        for (int pid : pids) {
            bool found_deleted = check_process_library_deleted(pid, lib_name);
            if (found_deleted) {
                return true;
            }
        }
    }

    return false;
}

std::string find_library_path(const std::string& lib_name, int pid) {
    int old_root_fd = -1;
    int old_cwd_fd = -1;
    bool did_chroot = false;
    std::string result;

    // If PID is specified, chroot to the process's root
    if (pid != -1) {
        // Save current working directory and root directory
        old_cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
        old_root_fd = open("/", O_RDONLY | O_DIRECTORY);

        if (old_root_fd < 0 || old_cwd_fd < 0) {
            std::cerr << "Warning: Failed to save current directories: " << strerror(errno) << std::endl;
            std::cerr << "Falling back to host filesystem search" << std::endl;
            if (old_root_fd >= 0) close(old_root_fd);
            if (old_cwd_fd >= 0) close(old_cwd_fd);
            old_root_fd = -1;
            old_cwd_fd = -1;
            // Fall through to normal search
        } else {
            // Chroot to process's root filesystem
            std::string proc_root = "/proc/" + std::to_string(pid) + "/root";
            if (chroot(proc_root.c_str()) == 0) {
                did_chroot = true;
                if (chdir("/") != 0) {
                    std::cerr << "Warning: Failed to chdir to new root: " << strerror(errno) << std::endl;
                }
                std::clog << "Chrooted to " << proc_root << " to search for " << lib_name << std::endl;
            } else {
                std::cerr << "Warning: chroot to " << proc_root << " failed: " << strerror(errno) << std::endl;
                std::cerr << "This usually requires root privileges or CAP_SYS_CHROOT capability" << std::endl;
                std::cerr << "Falling back to host filesystem search" << std::endl;
                close(old_root_fd);
                close(old_cwd_fd);
                old_root_fd = -1;
                old_cwd_fd = -1;
            }
        }
    }

    // First try to find the library using dlopen
    void* handle = dlopen(lib_name.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        // If not loaded, try to load it
        handle = dlopen(lib_name.c_str(), RTLD_LAZY);
    }

    if (handle) {
        // Get the path using dlinfo
        struct link_map* link_map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &link_map) == 0 && link_map) {
            std::string path = link_map->l_name;
            dlclose(handle);
            if (!path.empty() && path != lib_name) {
                std::clog << "Found library " << lib_name << " at: " << path << std::endl;
                result = path;
                goto cleanup;
            }
        }
        dlclose(handle);
    }

    // Fallback: search in common library directories
    {
        std::vector<std::string> search_dirs = {
            "/lib",
            "/lib64",
            "/lib64/ceph",
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib64/ceph",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu/ceph",
            "/usr/local/lib",
            "/snap/microceph/current/lib/x86_64-linux-gnu",
            "/snap/microceph/current/lib/x86_64-linux-gnu/ceph"
        };

        // Try different possible filenames for the library
        std::vector<std::string> possible_names;
        if (lib_name.find(".so") == std::string::npos) {
            // If no .so extension, try common patterns
            possible_names.push_back("lib" + lib_name + ".so");
            possible_names.push_back("lib" + lib_name + ".so.1");
            possible_names.push_back("lib" + lib_name + ".so.2");
        } else {
            possible_names.push_back(lib_name);
        }

        for (const auto& dir : search_dirs) {
            for (const auto& name : possible_names) {
                std::string full_path = dir + "/" + name;
                if (access(full_path.c_str(), F_OK) == 0) {
                    std::clog << "Found library " << lib_name << " at: " << full_path << std::endl;
                    result = full_path;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    // Restore original root and working directory if we chrooted
    if (did_chroot && old_root_fd >= 0) {
        // First restore the root filesystem
        if (fchdir(old_root_fd) != 0) {
            std::cerr << "Error: Failed to fchdir back to original root: " << strerror(errno) << std::endl;
        }
        if (chroot(".") != 0) {
            std::cerr << "Error: Failed to chroot back to original root: " << strerror(errno) << std::endl;
        }
        // Then restore the original working directory
        if (old_cwd_fd >= 0) {
            if (fchdir(old_cwd_fd) != 0) {
                std::cerr << "Error: Failed to restore original working directory: " << strerror(errno) << std::endl;
            }
        }
        std::clog << "Restored original root filesystem and working directory" << std::endl;
    }

    if (old_root_fd >= 0) {
        close(old_root_fd);
    }
    if (old_cwd_fd >= 0) {
        close(old_cwd_fd);
    }

    return result;
}

std::string find_executable_path(const std::string& exe_name) {
    // First check if exe_name is already an absolute path
    if (exe_name[0] == '/' && access(exe_name.c_str(), X_OK) == 0) {
        return exe_name;
    }

    // Always try /usr/bin first
    std::string usr_bin_path = "/usr/bin/" + exe_name;
    if (access(usr_bin_path.c_str(), X_OK) == 0) {
        std::clog << "Found executable " << exe_name << " at: " << usr_bin_path << std::endl;
        return usr_bin_path;
    }

    // Get PATH environment variable
    const char* path_env = getenv("PATH");
    if (path_env) {
        std::string path_str(path_env);
        std::vector<std::string> paths;

        // Split PATH by ':'
        size_t start = 0;
        size_t end = path_str.find(':');
        while (end != std::string::npos) {
            paths.push_back(path_str.substr(start, end - start));
            start = end + 1;
            end = path_str.find(':', start);
        }
        paths.push_back(path_str.substr(start));

        // Search in PATH directories
        for (const auto& dir : paths) {
            if (!dir.empty()) {
                std::string full_path = dir + "/" + exe_name;
                if (access(full_path.c_str(), X_OK) == 0) {
                    std::clog << "Found executable " << exe_name << " at: " << full_path << std::endl;
                    return full_path;
                }
            }
        }
    }

    // Fallback: search in other common system directories
    std::vector<std::string> common_dirs = {
        "/usr/local/bin",
        "/bin",
        "/sbin",
        "/usr/sbin",
        "/usr/local/sbin",
        "./bin/" // for local vstart cluster
    };

    for (const auto& dir : common_dirs) {
        std::string full_path = dir + "/" + exe_name;
        if (access(full_path.c_str(), X_OK) == 0) {
            std::clog << "Found executable " << exe_name << " at: " << full_path << std::endl;
            return full_path;
        }
    }

    return "";
}
bool check_process_executable_deleted(int pid, const std::string& exe_name) {
    // Check /proc/PID/exe symlink
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    char exe_target[PATH_MAX];
    ssize_t len = readlink(exe_path.c_str(), exe_target, sizeof(exe_target) - 1);

    if (len == -1) {
        // Could not read the symlink (process might not exist or no permission)
        return false;
    }

    exe_target[len] = '\0';
    std::string target_str(exe_target);

    // Check if the executable path contains "(deleted)"
    if (target_str.find("(deleted)") != std::string::npos) {
        // Also check if this is the executable we're looking for
        if (target_str.find(exe_name) != std::string::npos) {
            std::cerr << exe_name << " is deleted in process " << pid << std::endl;
            return true;
        }
    }

    return false;
}

bool check_executable_deleted(int process_id, const std::string& exe_name) {
    if (process_id > 0) {
        // Check specific process
        return check_process_executable_deleted(process_id, exe_name);
    } else {
        // Check all processes
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            std::cerr << "Error: Could not open /proc directory" << std::endl;
            return false;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            // Check if it's a numeric directory (process ID)
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                int pid = std::stoi(entry->d_name);

                // First check if this process is running the executable we're interested in
                std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
                char exe_target[PATH_MAX];
                ssize_t len = readlink(exe_path.c_str(), exe_target, sizeof(exe_target) - 1);

                if (len != -1) {
                    exe_target[len] = '\0';
                    std::string target_str(exe_target);

                    // Check if this process is running our target executable
                    if (target_str.find(exe_name) != std::string::npos) {
                        // Check if the executable is marked as deleted
                        if (target_str.find("(deleted)") != std::string::npos) {
                            std::cerr << exe_name << " is deleted in process " << pid << std::endl;
                            closedir(proc_dir);
                            return true;
                        }
                    }
                }
            }
        }
        closedir(proc_dir);
    }

    return false;
}
