"""Independent LIEF report of Mach-O chained fixups for HexSpell's opt-in tests.

Usage: lief_chained_fixups.py FILE SLICE

Prints TOML with the chained import names, every bind (slot address, symbol,
addend) and every rebase (slot address, unslid target). LIEF does not expose
arm64e signing fields, so those are checked structurally on the Rust side.
"""

import sys

import lief


def main() -> None:
    path, index = sys.argv[1], int(sys.argv[2])
    fat = lief.MachO.parse(path)
    if fat is None or index >= fat.size:
        sys.exit(f"cannot parse slice {index} of {path}")
    binary = fat.at(index)
    fixups = binary.dyld_chained_fixups
    if fixups is None:
        sys.exit(f"slice {index} of {path} has no LC_DYLD_CHAINED_FIXUPS")
    imports = [binding.symbol.name for binding in fixups.bindings]
    binds = sorted(
        f"{binding.address:#x} {binding.symbol.name} {binding.addend}"
        for binding in fixups.bindings
    )
    rebases = sorted(
        f"{reloc.address:#x} {reloc.target:#x}"
        for reloc in binary.relocations
        if isinstance(reloc, lief.MachO.RelocationFixup)
    )

    def array(values):
        return "[\n" + "".join(f'  "{v}",\n' for v in values) + "]"

    print(f"imports_count = {fixups.imports_count}")
    print(f"distinct_symbols = {len(set(imports))}")
    print(f"binds = {array(binds)}")
    print(f"rebases = {array(rebases)}")


if __name__ == "__main__":
    main()
