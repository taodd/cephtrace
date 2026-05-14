#!/usr/bin/env python3
"""Generate C++ header with embedded DWARF data from JSON files.

Reads all DWARF JSON files from files/ directory and generates
src/embedded_dwarf_data.h with static constexpr data structures
that can be compiled directly into the binaries.
"""

import json
import os
import sys
from pathlib import Path


def load_json_files(base_dir):
    """Load and categorize all JSON files by trace type."""
    osdtrace = []
    radostrace = []

    for json_path in sorted(Path(base_dir).rglob("*.json")):
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(
                f"Error: failed to parse {json_path}: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Determine trace type from directory structure
        rel = str(json_path.relative_to(base_dir))
        if "osdtrace" in rel:
            osdtrace.append(data)
        elif "radostrace" in rel:
            radostrace.append(data)

    return osdtrace, radostrace


def is_module_entry(val):
    """Return True if a top-level JSON value looks like a module entry.

    Top-level keys in the per-version JSON are either metadata
    (``version``, ``arch``, future additions) or per-module dicts that
    contain ``func2pc`` / ``func2vf``.  This predicate identifies the
    latter so the rest of the generator doesn't need a hard-coded
    metadata-key skip-list.
    """
    return isinstance(val, dict) and ("func2pc" in val or "func2vf" in val)


def analyze_limits(all_data):
    """Find maximum array sizes needed across all JSON files."""
    max_modules = 0
    max_funcs = 0
    max_var_fields = 0
    max_fields = 0

    for data in all_data:
        num_modules = 0
        for _key, val in data.items():
            if not is_module_entry(val):
                continue
            num_modules += 1
            if "func2pc" in val:
                max_funcs = max(max_funcs, len(val["func2pc"]))
            if "func2vf" in val:
                max_funcs = max(max_funcs, len(val["func2vf"]))
                for func_data in val["func2vf"].values():
                    vfs = func_data.get("var_fields", [])
                    max_var_fields = max(max_var_fields, len(vfs))
                    for vf in vfs:
                        max_fields = max(max_fields, len(vf.get("fields", [])))
        max_modules = max(max_modules, num_modules)

    return max_modules, max_funcs, max_var_fields, max_fields


def _c_str(s):
    """Quote and escape a Python string as a C string literal.

    Covers the escapes that actually occur in DWARF-demangled symbol names:
    ``\\"`` and ``\\\\``. ``json.dumps`` is reused because these common escapes
    match C; we pass ``ensure_ascii=False`` to keep any non-ASCII bytes as
    literal UTF-8 (``\\uXXXX`` emitted by JSON is not valid in narrow C string
    literals and would otherwise need extra handling).
    """
    return json.dumps(s, ensure_ascii=False)


def _generate_var_field(vf, indent):
    """Generate C++ initializer for one VarField entry."""
    loc = vf["location"]
    fields = vf.get("fields", [])
    fields_str = ", ".join(
        f'{{{f["offset"]}, {"true" if f["pointer"] else "false"}}}'
        for f in fields
    )
    stk = "true" if loc["stack"] else "false"
    loc_str = (
        f'{{{loc["reg"]}, '
        f'{loc["offset"]}, {stk}}}'
    )
    return (
        f'{indent}            {{'
        f'{loc_str}, '
        f'{len(fields)}, '
        f'{{{fields_str}}}}},')


def _generate_module(mod_name, mod_data, indent):
    """Generate C++ initializer for one module entry."""
    lines = []
    lines.append(f'{indent}    {{ // module: {mod_name}')
    lines.append(f'{indent}      {_c_str(mod_name)},')
    # Per-module ELF build-id (empty for legacy JSONs that pre-date the
    # build-id keying scheme; the embedded loader treats "" as
    # never-matches so legacy entries stay inert to the new lookup path).
    lines.append(f'{indent}      {_c_str(mod_data.get("build_id", ""))},')

    func2pc = mod_data.get("func2pc", {})
    lines.append(f'{indent}      {len(func2pc)}, // num_func2pc')
    lines.append(f'{indent}      {{ // func2pc')
    for func_name, addr in func2pc.items():
        lines.append(f'{indent}        {{{_c_str(func_name)}, {addr}}},')
    lines.append(f'{indent}      }},')

    func2vf = mod_data.get("func2vf", {})
    lines.append(f'{indent}      {len(func2vf)}, // num_func2vf')
    lines.append(f'{indent}      {{ // func2vf')
    for func_name, func_data in func2vf.items():
        var_fields = func_data.get("var_fields", [])
        lines.append(f'{indent}        {{ // {func_name}')
        lines.append(f'{indent}          {_c_str(func_name)},')
        lines.append(
            f'{indent}          {len(var_fields)},'
            ' // num_var_fields'
        )
        lines.append(f'{indent}          {{ // var_fields')
        for vf in var_fields:
            lines.append(_generate_var_field(vf, indent))
        lines.append(f'{indent}          }},')
        lines.append(f'{indent}        }},')
    lines.append(f'{indent}      }},')
    lines.append(f'{indent}    }},')
    return lines


def generate_version_entry(data, indent="    "):
    """Generate C++ initializer for one version entry."""
    version = data.get("version", "unknown")
    arch = data.get("arch", "")
    lines = [f'{indent}{{']
    lines.append(f'{indent}  {_c_str(version)},')
    # Per-version target architecture (empty for legacy JSONs).
    lines.append(f'{indent}  {_c_str(arch)},')

    modules = [
        (os.path.basename(k), v)
        for k, v in data.items() if is_module_entry(v)
    ]

    lines.append(f'{indent}  {len(modules)}, // num_modules')
    lines.append(f'{indent}  {{ // modules')
    for mod_name, mod_data in modules:
        lines.extend(_generate_module(mod_name, mod_data, indent))
    lines.append(f'{indent}  }},')
    lines.append(f'{indent}}},')
    return "\n".join(lines)


def generate_header(osdtrace, radostrace, limits):
    """Generate the complete C++ header file."""
    max_modules, max_funcs, max_var_fields, max_fields = limits
    header = f"""\
#ifndef EMBEDDED_DWARF_DATA_H
#define EMBEDDED_DWARF_DATA_H

// Auto-generated by tools/generate_embedded_dwarf.py
// Do not edit manually.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "bpf_ceph_types.h"

// Array size limits (derived from all known JSON files)
#define EMB_MAX_MODULES {max_modules}
#define EMB_MAX_FUNCS {max_funcs}
#define EMB_MAX_VAR_FIELDS {max_var_fields}
#define EMB_MAX_FIELDS {max_fields}

struct EmbeddedField {{
    int offset;
    bool pointer;
}};

struct EmbeddedVarField {{
    struct {{
        int reg;
        int offset;
        bool stack;
    }} location;
    int num_fields;
    EmbeddedField fields[EMB_MAX_FIELDS];
}};

struct EmbeddedFuncVF {{
    const char* func_name;
    int num_var_fields;
    EmbeddedVarField var_fields[EMB_MAX_VAR_FIELDS];
}};

struct EmbeddedFuncPC {{
    const char* func_name;
    uint64_t addr;
}};

struct EmbeddedModule {{
    const char* module_name;
    const char* build_id;       // Hex-encoded GNU build-id; "" for legacy entries.
    int num_func2pc;
    EmbeddedFuncPC func2pc[EMB_MAX_FUNCS];
    int num_func2vf;
    EmbeddedFuncVF func2vf[EMB_MAX_FUNCS];
}};

struct EmbeddedVersion {{
    const char* version;
    const char* arch;           // dpkg --print-architecture style; "" for legacy entries.
    int num_modules;
    EmbeddedModule modules[EMB_MAX_MODULES];
}};

"""

    # Generate osdtrace data
    header += (
        "static const EmbeddedVersion"
        " EMBEDDED_OSDTRACE_VERSIONS[] = {\n"
    )
    for data in osdtrace:
        header += generate_version_entry(data)
        header += "\n"
    header += "};\n\n"
    n_osd = len(osdtrace)
    header += (
        "static const int EMBEDDED_OSDTRACE_COUNT"
        f" = {n_osd};\n\n"
    )

    # Generate radostrace data
    header += (
        "static const EmbeddedVersion"
        " EMBEDDED_RADOSTRACE_VERSIONS[] = {\n"
    )
    for data in radostrace:
        header += generate_version_entry(data)
        header += "\n"
    header += "};\n\n"
    n_rados = len(radostrace)
    header += (
        "static const int EMBEDDED_RADOSTRACE_COUNT"
        f" = {n_rados};\n\n"
    )

    header += """\
#endif // EMBEDDED_DWARF_DATA_H
"""
    return header


def main():
    """Generate embedded DWARF data header from JSON files."""
    project_root = Path(__file__).parent.parent
    files_dir = project_root / "files"
    output_path = project_root / "src" / "embedded_dwarf_data.h"

    if not files_dir.exists():
        print(f"Error: {files_dir} not found", file=sys.stderr)
        sys.exit(1)

    osdtrace, radostrace = load_json_files(files_dir)
    n_osd = len(osdtrace)
    n_rados = len(radostrace)
    print(f"Loaded {n_osd} osdtrace + {n_rados} radostrace JSON files")

    all_data = osdtrace + radostrace
    limits = analyze_limits(all_data)
    max_modules, max_funcs, max_var_fields, max_fields = limits
    print(
        f"Limits: modules={max_modules},"
        f" funcs={max_funcs},"
        f" var_fields={max_var_fields},"
        f" fields={max_fields}"
    )

    header = generate_header(osdtrace, radostrace, limits)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header)

    print(f"Generated {output_path} ({len(header)} bytes)")


if __name__ == "__main__":
    main()
