#!/usr/bin/env python3
"""
Compare two dwarf JSON files for cephtrace testing.
Provides detailed comparison of func2pc and func2vf mappings.
"""

import json
import sys
from typing import Dict, Any, List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colored(text: str, color: str) -> str:
    """Return colored text for terminal output"""
    return f"{color}{text}{Colors.RESET}"


def compare_func2pc(file1_name: str, func2pc1: Dict[str, int],
                    file2_name: str, func2pc2: Dict[str, int],
                    binary_path: str) -> Tuple[bool, List[str]]:
    """
    Compare func2pc dictionaries (function name to program counter mappings).
    Returns (success, list of error messages)
    """
    errors = []

    funcs1 = set(func2pc1.keys())
    funcs2 = set(func2pc2.keys())

    # Check for missing functions
    only_in_1 = funcs1 - funcs2
    only_in_2 = funcs2 - funcs1

    if only_in_1:
        errors.append(f"Functions only in {file1_name}:")
        for func in sorted(only_in_1):
            errors.append(f"  - {func} (pc: {func2pc1[func]})")

    if only_in_2:
        errors.append(f"Functions only in {file2_name}:")
        for func in sorted(only_in_2):
            errors.append(f"  - {func} (pc: {func2pc2[func]})")

    # Compare PC values for common functions
    common_funcs = funcs1 & funcs2
    pc_mismatches = []

    for func in sorted(common_funcs):
        if func2pc1[func] != func2pc2[func]:
            pc_mismatches.append(
                f"  - {func}:\n"
                f"      {file1_name}: {func2pc1[func]} "
                f"(0x{func2pc1[func]:x})\n"
                f"      {file2_name}: {func2pc2[func]} "
                f"(0x{func2pc2[func]:x})"
            )

    if pc_mismatches:
        errors.append(f"Program counter mismatches:")
        errors.extend(pc_mismatches)

    return len(errors) == 0, errors


def compare_var_fields(file1_name: str, vf1: Dict[str, Any],
                       file2_name: str, vf2: Dict[str, Any],
                       func_name: str) -> Tuple[bool, List[str]]:
    """
    Compare var_fields for a specific function.
    Returns (success, list of error messages)
    """
    errors = []

    var_fields1 = vf1.get("var_fields", [])
    var_fields2 = vf2.get("var_fields", [])

    if len(var_fields1) != len(var_fields2):
        errors.append(
            f"  Different number of var_fields for {func_name}:\n"
            f"    {file1_name}: {len(var_fields1)}\n"
            f"    {file2_name}: {len(var_fields2)}"
        )
        return False, errors

    # Compare each var_field entry
    for i, (field1, field2) in enumerate(zip(var_fields1, var_fields2)):
        # Compare location
        loc1 = field1.get("location", {})
        loc2 = field2.get("location", {})

        if loc1 != loc2:
            errors.append(
                f"  Location mismatch for {func_name} var_field[{i}]:\n"
                f"    {file1_name}: {loc1}\n"
                f"    {file2_name}: {loc2}"
            )

        # Compare fields
        fields1 = field1.get("fields", [])
        fields2 = field2.get("fields", [])

        if fields1 != fields2:
            errors.append(
                f"  Fields mismatch for {func_name} var_field[{i}]:\n"
                f"    {file1_name}: {fields1}\n"
                f"    {file2_name}: {fields2}"
            )

    return len(errors) == 0, errors


def compare_func2vf(file1_name: str, func2vf1: Dict[str, Any],
                    file2_name: str, func2vf2: Dict[str, Any],
                    binary_path: str) -> Tuple[bool, List[str]]:
    """
    Compare func2vf dictionaries (function to variable fields mappings).
    Returns (success, list of error messages)
    """
    errors = []

    funcs1 = set(func2vf1.keys())
    funcs2 = set(func2vf2.keys())

    # Check for missing functions
    only_in_1 = funcs1 - funcs2
    only_in_2 = funcs2 - funcs1

    if only_in_1:
        errors.append(f"Functions only in {file1_name}:")
        for func in sorted(only_in_1):
            errors.append(f"  - {func}")

    if only_in_2:
        errors.append(f"Functions only in {file2_name}:")
        for func in sorted(only_in_2):
            errors.append(f"  - {func}")

    # Compare var_fields for common functions
    common_funcs = funcs1 & funcs2

    for func in sorted(common_funcs):
        success, func_errors = compare_var_fields(
            file1_name, func2vf1[func],
            file2_name, func2vf2[func],
            func
        )
        if not success:
            errors.extend(func_errors)

    return len(errors) == 0, errors


def compare_binary_data(file1_name: str, data1: Dict[str, Any],
                        file2_name: str, data2: Dict[str, Any],
                        binary_path: str) -> Tuple[bool, List[str]]:
    """
    Compare data for a specific binary path.
    Returns (success, list of error messages)
    """
    all_errors = []
    all_success = True

    # Compare func2pc
    if "func2pc" in data1 or "func2pc" in data2:
        func2pc1 = data1.get("func2pc", {})
        func2pc2 = data2.get("func2pc", {})

        success, errors = compare_func2pc(
            file1_name, func2pc1,
            file2_name, func2pc2,
            binary_path
        )

        if not success:
            all_success = False
            all_errors.append(
                colored(
                    f"\n[func2pc differences in {binary_path}]",
                    Colors.YELLOW
                )
            )
            all_errors.extend(errors)

    # Compare func2vf
    if "func2vf" in data1 or "func2vf" in data2:
        func2vf1 = data1.get("func2vf", {})
        func2vf2 = data2.get("func2vf", {})

        success, errors = compare_func2vf(
            file1_name, func2vf1,
            file2_name, func2vf2,
            binary_path
        )

        if not success:
            all_success = False
            all_errors.append(
                colored(
                    f"\n[func2vf differences in {binary_path}]",
                    Colors.YELLOW
                )
            )
            all_errors.extend(errors)

    return all_success, all_errors


def compare_dwarf_json(file1_path: str, file2_path: str,
                       verbose: bool = False) -> bool:
    """
    Compare two dwarf JSON files.
    Returns True if files are equivalent, False otherwise.
    """
    # Load JSON files
    try:
        with open(file1_path, 'r') as f:
            data1 = json.load(f)
    except FileNotFoundError:
        print(colored(f"Error: File not found: {file1_path}", Colors.RED))
        return False
    except json.JSONDecodeError as e:
        print(colored(f"Error: Invalid JSON in {file1_path}: {e}", Colors.RED))
        return False

    try:
        with open(file2_path, 'r') as f:
            data2 = json.load(f)
    except FileNotFoundError:
        print(colored(f"Error: File not found: {file2_path}", Colors.RED))
        return False
    except json.JSONDecodeError as e:
        print(colored(f"Error: Invalid JSON in {file2_path}: {e}", Colors.RED))
        return False

    # Compare top-level keys
    keys1 = set(data1.keys())
    keys2 = set(data2.keys())

    if keys1 != keys2:
        print(colored("Different top-level keys:", Colors.RED))
        only_in_1 = keys1 - keys2
        only_in_2 = keys2 - keys1

        if only_in_1:
            print(f"  Only in {file1_path}: {only_in_1}")
        if only_in_2:
            print(f"  Only in {file2_path}: {only_in_2}")
        return False

    # Compare version (informational only, not a failure)
    if "version" in data1 and "version" in data2:
        if data1["version"] != data2["version"]:
            if verbose:
                print(colored(
                    "Note: Version difference (informational only):",
                    Colors.BLUE
                ))
                print(f"  {file1_path}: {data1['version']}")
                print(f"  {file2_path}: {data2['version']}")

    # Compare each binary path
    all_success = True
    binary_paths = [k for k in keys1 if k != "version"]

    for binary_path in sorted(binary_paths):
        success, errors = compare_binary_data(
            file1_path, data1[binary_path],
            file2_path, data2[binary_path],
            binary_path
        )

        if not success:
            all_success = False
            for error in errors:
                print(error)

    return all_success


def main():
    """Main entry point"""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <reference_file.json> "
              f"<generated_file.json> [-v|--verbose]")
        print()
        print("Compare two dwarf JSON files for cephtrace testing.")
        print("Returns exit code 0 if files match, 1 otherwise.")
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    print(colored("Comparing dwarf JSON files:", Colors.BOLD))
    print(f"  Reference:  {file1}")
    print(f"  Generated:  {file2}")
    print()

    success = compare_dwarf_json(file1, file2, verbose)

    if success:
        print()
        print(colored("✓ Files match!", Colors.GREEN))
        sys.exit(0)
    else:
        print()
        print(colored("✗ Files differ!", Colors.RED))
        sys.exit(1)


if __name__ == "__main__":
    main()
