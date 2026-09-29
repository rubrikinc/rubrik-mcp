"""Verify a built wheel is consistent with server.json before it can publish.

The MCP Registry ties a PyPI package to a server name by finding
`mcp-name: <name>` in the PUBLISHED package description, which comes from
README.md via `readme` in pyproject.toml. PyPI metadata is immutable per
version, so every mismatch caught here is one that could not be fixed after
upload. Checks the built artifact rather than source files, since the source
can be correct while the metadata is not.

Usage: check_registry_metadata.py <wheel> [--tag vX.Y.Z]
"""

import json
import re
import sys
import zipfile
from email.parser import Parser


def main() -> int:
    args = sys.argv[1:]
    tag = None
    if "--tag" in args:
        i = args.index("--tag")
        tag = args[i + 1]
        del args[i : i + 2]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2

    with zipfile.ZipFile(args[0]) as z:
        meta_name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        meta = Parser().parsestr(z.read(meta_name).decode())
    description = meta.get_payload() or ""

    server = json.load(open("server.json"))
    name = server["name"]
    pypi = [p for p in server["packages"] if p["registryType"] == "pypi"]

    errors = []
    if len(pypi) != 1:
        errors.append(f"server.json should declare exactly one pypi package, found {len(pypi)}")
    else:
        pkg = pypi[0]
        if pkg["identifier"] != meta["Name"]:
            errors.append(f"server.json identifier {pkg['identifier']!r} != package name {meta['Name']!r}")
        if pkg["version"] != meta["Version"]:
            errors.append(f"server.json package version {pkg['version']!r} != package version {meta['Version']!r}")
    if server["version"] != meta["Version"]:
        errors.append(f"server.json version {server['version']!r} != package version {meta['Version']!r}")
    if tag is not None and tag != f"v{meta['Version']}":
        errors.append(f"tag {tag!r} != v{meta['Version']}")

    # Exact match with the boundary the registry requires after the name:
    # whitespace, an HTML tag, the comment close, or end of text. A plain
    # substring test would accept `.../rubrik-mcp-foo`.
    if not re.search(r"mcp-name:\s*" + re.escape(name) + r"(?=\s|<|-->|$)", description):
        errors.append(
            f"`mcp-name: {name}` not found in the package description "
            f"({len(description.strip())} chars). Check that README.md still contains "
            f'the marker comment and that pyproject.toml still sets readme = "README.md".'
        )

    if errors:
        print("Registry metadata check failed:", *errors, sep="\n  ", file=sys.stderr)
        return 1
    print(f"OK: {meta['Name']} {meta['Version']} matches server.json ({name}); "
          f"description is {len(description.strip()):,} chars")
    return 0


if __name__ == "__main__":
    sys.exit(main())
