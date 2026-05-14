#ifndef VERSION_UTILS_H
#define VERSION_UTILS_H

#include <string>

/**
 * Get the package version for a given library path by extracting the package name
 * and querying the system package manager (dpkg).
 * 
 * @param library_path The path to the library file
 * @return The version string, or "unknown" if version cannot be determined
 */
std::string get_package_version(const std::string& library_path);

/**
 * Check if a specific process has a library marked as deleted in its memory maps.
 * This indicates the library file has been updated on disk but the old version
 * is still loaded in memory.
 * 
 * @param pid The process ID to check
 * @param lib_name The name of the library to check for
 * @return true if the library is marked as deleted, false otherwise
 */
bool check_process_library_deleted(int pid, const std::string& lib_name);

/**
 * Check if any process (or a specific process) has a library marked as deleted
 * in memory. This function checks the specified process ID or scans all processes
 * if process_id is -1.
 * 
 * @param process_id The specific process ID to check (-1 to check all processes)
 * @param lib_name The name of the library to check for
 * @return true if any matching library is marked as deleted, false otherwise
 */
bool check_library_deleted(int process_id, const std::string& lib_name);

/**
 * Find the path to a dynamic library by name.
 * First tries to find the library using dlopen, then falls back to searching
 * common library directories if that fails.
 *
 * @param lib_name The name of the library to find (e.g., "librbd.so.1")
 * @param pid The process ID to search libraries for. If specified (not -1),
 *            temporarily chroots to /proc/<pid>/root to find the library
 *            in the process's filesystem (useful for containerized processes).
 *            Requires CAP_SYS_CHROOT capability.
 * @return The full path to the library, or empty string if not found
 */
std::string find_library_path(const std::string& lib_name, int pid = -1);

/**
 * Find the path to an executable by name.
 * Searches through common system paths and PATH environment variable.
 *
 * @param exe_name The name of the executable to find (e.g., "ceph-osd")
 * @return The full path to the executable, or empty string if not found
 */
std::string find_executable_path(const std::string& exe_name);

/**
 * Check if a specific process has an executable marked as deleted in its memory maps.
 * This indicates the executable file has been updated on disk but the old version
 * is still running in memory.
 *
 * @param pid The process ID to check
 * @param exe_name The name of the executable to check for
 * @return true if the executable is marked as deleted, false otherwise
 */
bool check_process_executable_deleted(int pid, const std::string& exe_name);

/**
 * Check if any process (or a specific process) has an executable marked as deleted
 * in memory. This function checks the specified process ID or scans all processes
 * if process_id is -1.
 *
 * @param process_id The specific process ID to check (-1 to check all processes)
 * @param exe_name The name of the executable to check for
 * @return true if any matching executable is marked as deleted, false otherwise
 */
bool check_executable_deleted(int process_id, const std::string& exe_name);

/**
 * Check if the Ceph version is squid (19.2.0) or above.
 * Parses version strings from dpkg (e.g., "19.2.0-0ubuntu0.22.04.1")
 * or rpm (e.g., "2:19.2.0-1.el9") formats.
 *
 * @param version The version string from get_package_version()
 * @return true if version >= 19.2.0, false otherwise
 */
bool is_ceph_version_squid_or_above(const std::string& version);

/**
 * Get the version string from a DWARF JSON file.
 *
 * @param json_file The path to the JSON file
 * @return The version string, or empty string if not found or error
 */
std::string get_version_from_json(const std::string& json_file);

/**
 * Read the GNU build-id from an ELF binary's `.note.gnu.build-id` section.
 *
 * Used as the lookup key for the embedded DWARF data registry.  Build-id is
 * unique per (source, toolchain, arch) build and is always present in
 * non-stripped binaries — and even survives `strip` by default because the
 * note lives in an allocated segment.
 *
 * @param path Absolute path to an ELF file.
 * @return Hex-encoded build-id (typically 40 chars for GNU ld's 160-bit SHA1,
 *         32 chars for LLD's xxhash variant), or empty string on any error
 *         (file unreadable, not an ELF, no build-id note).
 */
std::string get_elf_build_id(const std::string& path);

/**
 * Return the running host's architecture using `dpkg --print-architecture`'s
 * naming convention so the value round-trips with package metadata:
 *   x86_64  → "amd64"
 *   aarch64 → "arm64"
 *   ppc64le → "ppc64el"
 *   s390x   → "s390x"
 *   armv7l  → "armhf"
 *   i686    → "i386"
 *   anything else → uname.machine verbatim
 *
 * @return Architecture string, or empty string if uname(2) fails.
 */
std::string get_host_arch();

/**
 * Print the version banner for a cephtrace tool to stdout.
 *
 * For a tagged release tarball (no embedded git metadata) prints just the
 * point release, e.g.
 *
 *     osdtrace 1.4
 *     Built: 2026-05-13
 *
 * For a development build (compiled from a git checkout) it additionally
 * shows which point release the build is derived from plus the git locator,
 * e.g.
 *
 *     osdtrace 1.4 (development build)
 *     Based on:  cephtrace 1.4
 *     Git:       v1.4-3-gabc1234-dirty (branch main)
 *     Built:     2026-05-13
 *
 * @param tool_name The name to display (e.g. "osdtrace", "radostrace").
 */
void print_tool_version(const char* tool_name);

#endif // VERSION_UTILS_H
