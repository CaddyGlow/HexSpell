"""Read an in-memory PE from stdin and report independent load-config expectations."""

import sys

import pefile

with pefile.PE(data=sys.stdin.buffer.read(), fast_load=True) as image:
    image.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
    )
    config = image.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    print(f"cookie = {config.SecurityCookie}")
    print(f"cookie_offset = {config.get_field_absolute_offset('SecurityCookie')}")
    print(f"edit_list = {config.EditList}")
    print(f"edit_list_offset = {config.get_field_absolute_offset('EditList')}")
