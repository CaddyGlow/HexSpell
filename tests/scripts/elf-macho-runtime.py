#!/usr/bin/env python3
"""Generate, independently inspect and run the delivered writer profiles.

Run from the repository root with Cargo and readelf on PATH. Mach-O output is
structurally inspected on Linux; this harness never claims macOS acceptance.
"""
import argparse
import ctypes
import os
import pathlib
import platform
import shutil
import subprocess
import sys


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        result.check_returncode()
    return result.stdout


def generate(example, *args):
    run('cargo', 'run', '--locked', '--features', 'elf,macho,write', '--example', example, '--', *map(str, args))


def inspect(path):
    print(run(sys.executable, 'tests/scripts/inspect_generated_images.py', str(path)), end='')
    if tool := shutil.which('llvm-readobj'):
        run(tool, '--file-headers', '--sections', '--symbols', str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    print(run('rustc', '--version'), end='')
    print(run('readelf', '--version').splitlines()[0])
    if tool := shutil.which('llvm-readobj'):
        print(run(tool, '--version').strip())
    hello = output / 'elf-hello'
    edited = output / 'elf-hello-edited'
    generate('elf_hello', hello)
    inspect(hello)
    run('readelf', '-h', '-l', '-S', '-s', str(hello))
    generate('elf_edit', hello, edited)
    inspect(edited)
    if platform.system() == 'Linux' and platform.machine() == 'x86_64':
        before = run(str(hello))
        after = run(str(edited))
        if before != after or before != 'Hello, ELF!\n':
            raise ValueError(f'hello/edit runtime disagreement: {before!r}, {after!r}')
        print('Linux AMD64 hello and transactional edit: passed')
        for stripped in (False, True):
            path = output / ('elf-pie-stripped' if stripped else 'elf-pie')
            generate('elf_pie', path, *(['--stripped'] if stripped else []))
            inspect(path)
            if run(str(path)) != 'Hello, ELF!\n':
                raise ValueError('PIE imported write failed')
        shared = output / 'libhexspell.so'
        generate('elf_shared', shared)
        inspect(shared)
        run('readelf', '-d', '-s', '-r', str(shared))
        second = output / 'libhexspell-second.so'
        shutil.copyfile(shared, second)
        libraries = [ctypes.CDLL(str(path)) for path in (shared, second)]
        addresses = []
        for library in libraries:
            library.answer.restype = ctypes.c_int
            library.imported_pid.restype = ctypes.c_int
            if library.answer() != 42 or library.imported_pid() != os.getpid():
                raise ValueError('shared export/import call failed')
            pointer = ctypes.c_void_p.in_dll(library, 'answer_pointer').value
            if ctypes.CFUNCTYPE(ctypes.c_int)(pointer)() != 42:
                raise ValueError('shared pointer symbol relocation failed')
            if ctypes.c_uint64.in_dll(library, 'initialized_marker').value != 0x12345678:
                raise ValueError('shared initialized data mismatch')
            if ctypes.c_uint64.in_dll(library, 'zero_marker').value != 0:
                raise ValueError('shared zero-fill data mismatch')
            addresses.append(ctypes.cast(library.answer, ctypes.c_void_p).value)
        if addresses[0] == addresses[1]:
            raise ValueError('shared relocation check needs distinct load addresses')
        print('Linux AMD64 PIE (including sectionless), imports, shared exports, zero-fill and relocation at distinct load addresses: passed')
        loader = output / 'native-loader'
        run('cc', '-Wall', '-Wextra', '-Werror', '-pthread', 'tests/scripts/native-loader.c', '-ldl', '-o', str(loader))
        print(run(str(loader), 'runtime', str(shared)), end='')
        edited_shared = output / 'libhexspell-edited.so'
        generate('elf_edit', shared, edited_shared)
        inspect(edited_shared)
        print(run(str(loader), 'runtime', str(edited_shared)), end='')
        stripped_shared = output / 'libhexspell-stripped.so'
        generate('elf_shared', stripped_shared, '--stripped')
        inspect(stripped_shared)
        print(run(str(loader), 'runtime', str(stripped_shared)), end='')
        override = output / 'libhexspell-preempt.so'
        run('cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
            'tests/scripts/elf-preempt.c', '-o', str(override))
        # Isolate RTLD_GLOBAL interposition from the ordinary loader checks above.
        print(run(sys.executable, '-c', r"""
import ctypes, sys, _ctypes
preempt = ctypes.CDLL(sys.argv[1], mode=ctypes.RTLD_GLOBAL)
image = ctypes.CDLL(sys.argv[2])
assert ctypes.c_int.in_dll(preempt, 'init_order').value == 12
image.answer.restype = ctypes.c_int
assert image.answer() == 42
pointer = ctypes.c_void_p.in_dll(image, 'answer_pointer').value
assert ctypes.CFUNCTYPE(ctypes.c_int)(pointer)() == 99
_ctypes.dlclose(image._handle)
assert ctypes.c_int.in_dll(preempt, 'fini_order').value == 21
print('Linux AMD64 pointer and lifecycle symbol preemption: passed')
""", str(override), str(shared)), end='')

    else:
        print('Linux AMD64 runtime: unavailable on this host')
    for target in ('x86_64', 'arm64'):
        path = output / f'macho-{target}'
        generate('macho_hello', target, path)
        inspect(path)
    print('macOS native execution, dyld and signing: NOT VALIDATED')


if __name__ == '__main__':
    main()
