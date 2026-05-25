import os

SUSPICIOUS_PATTERNS = [
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"powershell -enc",
    b"cmd.exe /c",
]

def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read(2_000_000)

            for p in SUSPICIOUS_PATTERNS:
                if p in data:
                    return True, f"Custom pattern: {p.decode(errors='ignore')}"
    except:
        pass

    return False, None