#!/usr/bin/env python3
"""Compare ELF signature containers with Linux scripts/sign-file and OpenSSL CMS.

Run from the repository root. Requires Cargo, a C compiler, OpenSSL, and a supplied
Linux sign-file executable. Uses a synthetic relocatable object, never loads a
kernel module, and writes only test keys/certificates and generated outputs.
"""
import argparse
import json
import pathlib
import subprocess
import sys


def run(*args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=600)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        result.check_returncode()
    return result.stdout


def example(*args):
    run('cargo', 'run', '--locked', '--features', 'elf,write', '--example', 'elf_signature', '--', *args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=pathlib.Path)
    parser.add_argument('--sign-file', required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sign_file = args.sign_file.resolve()
    source = output / 'probe.c'
    unsigned = output / 'unsigned.ko'
    source.write_text('int hexspell_signature_probe(void) { return 42; }\n')
    run('cc', '-c', source, '-o', unsigned)
    key = output / 'test.key'
    cert = output / 'test.pem'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
        '-out', cert, '-days', '1', '-subj', '/CN=HexSpell-appended-signature-test')
    report = {'oracle': str(sign_file), 'gates': {}}
    for digest in ('sha256', 'sha512'):
        signed = output / f'{digest}-signed.ko'
        attached = output / f'{digest}-attached.ko'
        copied = output / f'{digest}-roundtrip.ko'
        payload = output / f'{digest}-payload.ko'
        signature = output / f'{digest}-signature.p7s'
        removed = output / f'{digest}-removed.ko'
        verified = output / f'{digest}-verified.ko'
        run(sign_file, '-p', digest, key, cert, unsigned, signed)
        example('attach', unsigned, str(unsigned) + '.p7s', attached)
        example('roundtrip', signed, copied)
        if signed.read_bytes() != attached.read_bytes() or signed.read_bytes() != copied.read_bytes():
            raise ValueError(f'{digest}: HexSpell differs from Linux sign-file')
        example('extract', attached, payload, signature)
        example('remove', attached, removed)
        if unsigned.read_bytes() != payload.read_bytes() or unsigned.read_bytes() != removed.read_bytes():
            raise ValueError(f'{digest}: signed prefix was changed')
        run('openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', signature,
            '-content', payload, '-certfile', cert, '-noverify', '-out', verified)
        if verified.read_bytes() != unsigned.read_bytes():
            raise ValueError(f'{digest}: CMS verified a different payload')
        report['gates'][digest] = 'passed'
    (output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
