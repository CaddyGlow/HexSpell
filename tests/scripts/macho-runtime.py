#!/usr/bin/env python3
"""Native macOS writer acceptance, including signing, edits and FAT extraction.

Run on macOS from the repository root. An arm64 host with Rosetta can pass
--arch x86_64 for the second CPU profile. Each requested gate fails on error;
structural checks never substitute for native execution.
"""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import struct
import sys


def run(*args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=600)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        result.check_returncode()
    return result.stdout


def example(name, *args):
    return run('cargo', 'run', '--locked', '--features', 'macho,write', '--example', name, '--', *args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=pathlib.Path)
    parser.add_argument('--arch', choices=('arm64', 'x86_64'))
    parser.add_argument('--core-only', action='store_true', help='run only linkage/signing checks')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('native acceptance requires macOS')
    target = args.arch or platform.machine()
    output = args.output.resolve() / target
    output.mkdir(parents=True, exist_ok=True)
    report = {'platform': platform.platform(), 'architecture': target, 'deployment': 'macOS 13.0', 'gates': {}}
    prefix = ['/usr/bin/arch', '-x86_64'] if target == 'x86_64' and platform.machine() == 'arm64' else []
    report['execution_engine'] = 'Rosetta 2' if prefix else 'native'
    report['rustc'] = run('rustc', '--version').strip()
    report['clang'] = run('clang', '--version').splitlines()[0]
    report['apple_sdk'] = run('xcrun', '--show-sdk-version').strip()
    report['apple_tools'] = {tool: run('xcrun', '--find', tool).strip() for tool in ('codesign', 'otool', 'dyld_info')}


    def inspect(path):
        run(sys.executable, 'tests/scripts/inspect_generated_images.py', path)
        (output / (path.name + '.otool.txt')).write_text(run('otool', '-l', path))
        dyld = run('dyld_info', '-exports', '-imports', '-fixups', path)
        (output / (path.name + '.dyld.txt')).write_text(dyld)
        if any(message in dyld.lower() for message in ('malformed', 'mis-aligned', 'invalid ', 'error:')):
            raise ValueError(f'dyld_info rejected {path}: {dyld}')
        example('macho_validate', 'validate', path)

    def sign(path):
        os.chmod(path, 0o755)
        run('codesign', '--force', '--sign', '-', '--timestamp=none', path)
        run('codesign', '--verify', '--strict', path)
        inspect(path)

    hello = output / 'hello'
    library = output / 'libhexspell.dylib'
    example('macho_hello', target, hello)
    inspect(hello)
    sign(hello)
    if run(*prefix, hello) != 'Hello, Mach-O!\n':
        raise ValueError('native imported hello output mismatch')
    report['gates']['hello_import_sign_reparse'] = 'passed'

    example('macho_dylib', target, library)
    inspect(library)
    sign(library)
    loader = output / 'native-loader'
    run('clang', '-arch', target, '-mmacosx-version-min=13.0', '-Wall', '-Wextra', '-Werror', '-pthread', 'tests/scripts/native-loader.c', '-o', loader)
    run(*prefix, loader, 'core', library)
    report['gates']['dylib_export_import_relocated_pointer_data'] = 'passed'
    if args.core_only:
        print(json.dumps(report, indent=2))
        return
    run(*prefix, loader, 'runtime', library)
    report['gates']['constructors_finalizers_tls_unwind'] = 'passed'

    edited = output / 'libhexspell-edited.dylib'
    example('macho_edit', library, edited, 'strip')
    sign(edited)
    run(*prefix, loader, 'runtime', edited)
    report['gates']['edited_signed_dylib_runtime'] = 'passed'
    edited_hello = output / 'hello-edited'
    example('macho_edit', hello, edited_hello, 'strip')
    sign(edited_hello)
    if run(*prefix, edited_hello) != 'Hello, Mach-O!\n':
        raise ValueError('edited native hello output mismatch')
    report['gates']['edited_signed_executable_runtime'] = 'passed'

    other = 'arm64' if target == 'x86_64' else 'x86_64'
    other_library = output / f'libhexspell-{other}.dylib'
    example('macho_dylib', other, other_library)
    sign(other_library)
    fat = output / 'libhexspell-fat.dylib'
    example('macho_validate', 'pack', fat, library, other_library)
    rebuilt_fat = output / 'libhexspell-fat-rebuilt.dylib'
    example('macho_edit', fat, rebuilt_fat, 'strip', 'fat=0')
    extracted = output / 'libhexspell-extracted.dylib'
    example('macho_validate', 'extract', rebuilt_fat, '0', extracted)
    unchanged = output / 'libhexspell-unchanged.dylib'
    example('macho_validate', 'extract', rebuilt_fat, '1', unchanged)
    if unchanged.read_bytes() != other_library.read_bytes():
        raise ValueError('FAT rebuild changed unselected thin bytes')
    sign(extracted)
    run(*prefix, loader, 'runtime', extracted)
    report['gates']['fat_pack_extract_runtime'] = 'passed'

    reference_source = output / 'reference.c'
    reference_source.write_text('#include <stdio.h>\nint main(void) { puts("reference"); return 0; }\n')
    reference = output / 'reference'
    run('clang', '-arch', target, '-mmacosx-version-min=13.0', reference_source, '-o', reference)
    (output / 'reference.otool.txt').write_text(run('otool', '-l', reference))
    (output / 'reference.dyld.txt').write_text(run('dyld_info', '-exports', '-imports', '-fixups', reference))
    def profile(path):
        data = path.read_bytes()
        header = struct.unpack_from('<8I', data)
        if header[0] != 0xfeedfacf or header[3] != 2:
            raise ValueError('reference/generated executable has wrong magic/type')
        commands = {}
        pos = 32
        for _ in range(header[4]):
            cmd, size = struct.unpack_from('<II', data, pos)
            commands[cmd] = (pos, size)
            pos += size
        required = (0xe, 0x32, 0x80000034, 0x80000033, 0x80000028)
        if not all(cmd in commands for cmd in required):
            raise ValueError('reference/generated executable lacks matching dyld command profile')
        build = commands[0x32][0]
        platform_id, minimum = struct.unpack_from('<II', data, build + 8)
        dylinker = commands[0xe][0]
        name_offset = struct.unpack_from('<I', data, dylinker + 8)[0]
        name_start = dylinker + name_offset
        dylinker_name = data[name_start:data.index(0, name_start)].decode()
        chain_cmd = commands[0x80000034][0]
        chain_offset = struct.unpack_from('<I', data, chain_cmd + 8)[0]
        version, starts_offset, _, _, _, imports_format, symbols_format = struct.unpack_from('<7I', data, chain_offset)
        starts = chain_offset + starts_offset
        segments = struct.unpack_from('<I', data, starts)[0]
        pointer_formats = []
        for i in range(segments):
            offset = struct.unpack_from('<I', data, starts + 4 + i * 4)[0]
            if offset:
                pointer_formats.append(struct.unpack_from('<H', data, starts + offset + 6)[0])
        if version != 0 or imports_format != 1 or symbols_format != 0 or not pointer_formats or set(pointer_formats) != {6}:
            raise ValueError('reference/generated executable uses different chained-fixup conventions')
        return {'cpu': header[1], 'platform': platform_id, 'minimum': minimum, 'dylinker': dylinker_name, 'pointer_formats': sorted(set(pointer_formats))}
    generated_profile = profile(hello)
    reference_profile = profile(reference)
    expected_cpu = {'arm64': 0x100000c, 'x86_64': 0x1000007}[target]
    expected = {'cpu': expected_cpu, 'platform': 1, 'minimum': 13 << 16, 'dylinker': '/usr/lib/dyld', 'pointer_formats': [6]}
    if generated_profile != expected or reference_profile != expected:
        raise ValueError(f'linker profile mismatch: generated={generated_profile}, reference={reference_profile}')
    report['linker_reference_profile'] = reference_profile
    report['gates']['linker_reference_inspection'] = 'passed'
    (output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
