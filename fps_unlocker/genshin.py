import ctypes
from ctypes import wintypes
from unlocker_constants import *

kernel32 = ctypes.windll.kernel32


def pattern_scan(module_handle, signature):
    pattern = signature.encode('utf-8')
    pattern_bytes = []
    mask = []
    for byte in pattern.split(b' '):
        if byte == b'?':
            pattern_bytes.append(0)
            mask.append(0)
        else:
            pattern_bytes.append(int(byte, 16))
            mask.append(1)

    module = ctypes.c_void_p(module_handle)
    dos_header = ctypes.cast(module, ctypes.POINTER(
        wintypes.IMAGE_DOS_HEADER)).contents
    nt_headers = ctypes.cast(ctypes.c_void_p(
        module.value + dos_header.e_lfanew), ctypes.POINTER(wintypes.IMAGE_NT_HEADERS)).contents

    size_of_image = nt_headers.OptionalHeader.SizeOfImage
    scan_bytes = (ctypes.c_ubyte * size_of_image).from_address(module_handle)

    pattern_length = len(pattern_bytes)
    for i in range(size_of_image - pattern_length + 1):
        found = True
        for j in range(pattern_length):
            if mask[j] and scan_bytes[i + j] != pattern_bytes[j]:
                found = False
                break
        if found:
            return ctypes.cast(ctypes.byref(scan_bytes, i), ctypes.c_void_p).value
    return 0


# Example usage:
if __name__ == "__main__":
    module_name = "module_name_here.dll"
    module_handle = kernel32.GetModuleHandleW(module_name)
    if module_handle:
        signature = "12 34 ?? 56 ?? 78"
        result = pattern_scan(module_handle, signature)
        if result:
            print(f"Pattern found at: {hex(result)}")
        else:
            print("Pattern not found.")
    else:
        print(f"Module '{module_name}' not found.")
