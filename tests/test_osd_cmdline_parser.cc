#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "utils.h"

int main() {
    std::cout << "Running unit tests for parse_osd_id_from_tokens..." << std::endl;

    // Test 1: Standard --id 0 (separate tokens)
    {
        std::vector<std::string> args = {"ceph-osd", "--id", "0", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 0);
        std::cout << "  [PASS] Test 1: --id 0 -> 0" << std::endl;
    }

    // Test 2: Assignment --id=5
    {
        std::vector<std::string> args = {"ceph-osd", "--id=5", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 5);
        std::cout << "  [PASS] Test 2: --id=5 -> 5" << std::endl;
    }

    // Test 3: Standard -i 12 (separate tokens)
    {
        std::vector<std::string> args = {"ceph-osd", "-i", "12", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 12);
        std::cout << "  [PASS] Test 3: -i 12 -> 12" << std::endl;
    }

    // Test 4: Combined -i3 (no space)
    {
        std::vector<std::string> args = {"ceph-osd", "-i3", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 3);
        std::cout << "  [PASS] Test 4: -i3 -> 3" << std::endl;
    }

    // Test 5: Cephadm style -n osd.42
    {
        std::vector<std::string> args = {"ceph-osd", "-n", "osd.42", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 42);
        std::cout << "  [PASS] Test 5: -n osd.42 -> 42" << std::endl;
    }

    // Test 6: Cephadm style --name osd.7
    {
        std::vector<std::string> args = {"ceph-osd", "--name", "osd.7", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 7);
        std::cout << "  [PASS] Test 6: --name osd.7 -> 7" << std::endl;
    }

    // Test 7: Assignment --name=osd.99
    {
        std::vector<std::string> args = {"ceph-osd", "--name=osd.99", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == 99);
        std::cout << "  [PASS] Test 7: --name=osd.99 -> 99" << std::endl;
    }

    // Test 8: Long command line (>200 bytes) - tests fix for 199-byte truncation bug
    {
        std::vector<std::string> args = {"ceph-osd"};
        for (int i = 0; i < 50; ++i) {
            args.push_back("--gconf-ceph-some-extremely-long-config-flag-that-takes-up-bytes=" + std::to_string(i));
        }
        args.push_back("--id");
        args.push_back("77");
        int id = parse_osd_id_from_tokens(args);
        assert(id == 77);
        std::cout << "  [PASS] Test 8: Long cmdline (>200 bytes) -> 77" << std::endl;
    }

    // Test 9: No OSD ID specified
    {
        std::vector<std::string> args = {"ceph-osd", "--cluster", "ceph", "-f"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == -1);
        std::cout << "  [PASS] Test 9: No OSD ID -> -1" << std::endl;
    }

    // Test 10: Non-numeric OSD ID (exception safety)
    {
        std::vector<std::string> args = {"ceph-osd", "--id", "invalid_id"};
        int id = parse_osd_id_from_tokens(args);
        assert(id == -1);
        std::cout << "  [PASS] Test 10: Non-numeric ID -> -1" << std::endl;
    }

    std::cout << "ALL 10 UNIT TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
