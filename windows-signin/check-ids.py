#!/usr/bin/env python3
"""SohobOTP Sign-in: every place that names the provider's id must agree (run by CI).

The C++ code has two GUID definitions (the provider itself, and the key its settings and history
are read from), the configuration readers name the key as text, and the installer and the agent
write there. multiOTP's own id left in one of them made the sign-in screen read an empty key.
"""
import pathlib, re, sys

root = pathlib.Path(__file__).resolve().parent
repo = root.parent

def guid_from_define(path, name):
    text = (root / path).read_text(encoding="latin-1")
    m = re.search(r"DEFINE_GUID\(\s*" + name + r"\s*,([^)]*)\)", text)
    if not m:
        sys.exit(f"{path}: {name} not found")
    p = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
    return "{%08X-%04X-%04X-%02X%02X-%s}" % (p[0], p[1], p[2], p[3], p[4], "".join("%02X" % b for b in p[5:11]))

expected = guid_from_define("CredentialProvider/guid.h", "CLSID_CSample")  # the provider itself
found = {
    "CredentialProvider/guid.h CLSID_CSample": expected,
    "CredentialProviderFilter/guid.h CLSID_COTP_LOGON": guid_from_define("CredentialProviderFilter/guid.h", "CLSID_COTP_LOGON"),
    "CppClientCore/CppClientCore/guid.h CLSID_Multiotp": guid_from_define("CppClientCore/CppClientCore/guid.h", "CLSID_Multiotp"),
}
filter_id = guid_from_define("CredentialProviderFilter/guid.h", "CLSID_CSample")  # the filter, a second component
text_files = [
    "CppClientCore/CppClientCore/MultiOTPConfiguration.cpp",
    "CredentialProvider/Configuration.cpp",
    "Shared/Shared.cpp",
    "CredentialProviderFilter/CCredentialProviderFilter.cpp",
    "WixInstall/multiOTPCredentialProviderInstaller/Product.wxs",
]
for f in text_files:
    ids = {"{" + g.upper() + "}" for g in re.findall(r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
                                                    (root / f).read_text(encoding="latin-1"))
           if g.upper().startswith(("B3D2C6A1", "FCEFDFAB"))}
    # each file names the provider; the installer also registers the filter
    found[f] = expected if ids and ids <= {expected, filter_id} and expected in ids else ", ".join(sorted(ids)) or "none"
agent = (repo / "agent/internal/winapply/winapply.go").read_text(encoding="utf-8")
ids = {"{" + g.upper() + "}" for g in re.findall(r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}", agent)}
found["agent/internal/winapply/winapply.go"] = expected if ids == {expected} else ", ".join(sorted(ids)) or "none"

bad = {k: v for k, v in found.items() if v != expected}
for k, v in sorted(found.items()):
    print(("OK   " if v == expected else "FAIL ") + k + " " + v)
if bad or len(found) < 7:
    sys.exit("provider id mismatch (expected %s everywhere)" % expected)
print("all provider ids are " + expected)
