#!/usr/bin/env python3
"""Collect complete source notices from Cargo's locked, target-filtered normal graph.

No network requests, builds, credentials, or application data are used. Published
crate notices are combined with checked-in, hash-verified upstream references.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


NOTICE_NAME = re.compile(r"^(?:licen[sc]e|copying|copyright|notice|ofl)(?:$|[._-])", re.I)
FONT_NOTICES = (
    "fonts/Hack-Regular.txt",
    "fonts/OFL.txt",
    "fonts/UFL.txt",
    "fonts/emoji-icon-font-mit-license.txt",
)


def normal_packages(metadata):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    root_id = metadata["resolve"]["root"]
    pending = [root_id]
    seen = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return sorted(
        (packages[package_id] for package_id in seen if package_id != root_id),
        key=lambda package: (package["name"], package["version"]),
    )


def upstream_references(project_root):
    references = {}
    for index_path in sorted((project_root / "licenses/upstream").glob("**/index.json")):
        index = json.loads(index_path.read_text(encoding="utf-8"))
        for package, entries in index["packages"].items():
            if package in references:
                raise ValueError("Duplicate upstream notice mapping: " + package)
            references[package] = entries
    return references


def read_document(path):
    content = path.read_bytes()
    if not content.strip() or len(content) > 1024 * 1024:
        raise ValueError("Notice is empty or exceeds the document limit: " + path.name)
    return content, content.decode("utf-8-sig")


def package_documents(package, references, project_root):
    project_root = project_root.resolve()
    package_root = Path(package["manifest_path"]).parent
    key = package["name"] + "@" + package["version"]
    files = set()
    for path in package_root.rglob("*"):
        if not path.is_file():
            continue
        in_license_directory = any(part.lower() in ("license", "licenses") for part in path.relative_to(package_root).parts[:-1])
        if NOTICE_NAME.match(path.name) or (in_license_directory and path.suffix.lower() in (".txt", ".md")):
            if path.suffix.lower() not in (".rs", ".c", ".h", ".py"):
                files.add(path)
    if package.get("license_file"):
        files.add(package_root / package["license_file"])
    if package["name"] == "epaint_default_fonts":
        for relative in FONT_NOTICES:
            path = package_root / relative
            if not path.is_file():
                raise ValueError(key + " is missing a required embedded-font notice: " + relative)
            files.add(path)

    documents = []
    for path in sorted(files):
        content, text = read_document(path)
        relative = path.relative_to(package_root).as_posix()
        documents.append(("crate-file", relative, hashlib.sha256(content).hexdigest(), text))

    for entry in references.get(key, []):
        path = (project_root / entry["path"]).resolve()
        path.relative_to(project_root)
        content, text = read_document(path)
        digest = hashlib.sha256(content).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError("Upstream notice checksum mismatch: " + entry["path"])
        coverage = entry.get("coverage", "pinned-upstream-file")
        locator = entry["url"]
        if entry.get("note"):
            locator += "\nProvenance note: " + entry["note"]
        documents.append((coverage, locator, digest, text))

    if package["name"] == "libsqlite3-sys":
        source = package_root / "sqlite3/sqlite3.c"
        with source.open("r", encoding="utf-8") as handle:
            header = handle.read(128 * 1024)
        notice = re.search(r"/\*\n\*\* 2001 September 15.*?\*/", header, re.S)
        if not notice or "author disclaims copyright" not in notice.group():
            raise ValueError(key + " bundled SQLite copyright disclaimer needs review")
        text = notice.group()
        documents.append(("bundled-source-notice", "sqlite3/sqlite3.c initial copyright disclaimer", hashlib.sha256(text.encode()).hexdigest(), text))

    if not documents:
        raise ValueError(key + " has no complete notice file or verified upstream reference")
    return documents


def render_notices(metadata, project_root, target):
    references = upstream_references(project_root)
    packages = normal_packages(metadata)
    sections = [
        "THIRD-PARTY NOTICES",
        "Target: " + target,
        "Cargo.lock SHA-256: " + hashlib.sha256((project_root / "Cargo.lock").read_bytes()).hexdigest(),
        "Scope: target-filtered normal dependencies, including their proc-macro dependencies.",
        "Build-only and dev-only dependency edges are excluded.",
        "Coverage records preserve supplied notices and referenced terms; they are not a legal opinion.",
        "An upstream-reference may contain the upstream template's unfilled placeholders. They are not reconstructed copyright notices.",
    ]
    failures = []
    for package in packages:
        key = package["name"] + "@" + package["version"]
        try:
            documents = package_documents(package, references, project_root)
        except (OSError, ValueError) as error:
            failures.append(str(error))
            continue
        package_root = Path(package["manifest_path"]).parent
        vcs_path = package_root / ".cargo_vcs_info.json"
        revision = json.loads(vcs_path.read_text(encoding="utf-8")).get("git", {}).get("sha1", "not supplied") if vcs_path.is_file() else "not supplied"
        sections.extend([
            "\n" + "=" * 78,
            "Package: " + key,
            "Declared license: " + (package.get("license") or "see supplied license file"),
            "Authors (package metadata, not a reconstructed copyright statement): " + "; ".join(package.get("authors", [])),
            "Repository: " + (package.get("repository") or "not supplied"),
            "Source revision: " + revision,
            "Crate source: https://crates.io/crates/" + package["name"] + "/" + package["version"],
        ])
        for coverage, locator, digest, text in documents:
            sections.extend([
                "\n--- Notice ---",
                "Coverage: " + coverage,
                "Source: " + locator,
                "Source SHA-256: " + digest,
                "\n" + text + ("" if text.endswith("\n") else "\n"),
            ])
    if failures:
        raise ValueError("Cannot generate complete notices:\n- " + "\n- ".join(failures))
    return "\n".join(sections) + "\n", len(packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Rust target triple matching the built binary")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.target):
        parser.error("target must be a Rust target triple")
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", args.target],
        cwd=project_root, capture_output=True, encoding="utf-8", check=False,
    )
    if result.returncode:
        raise ValueError("Cargo metadata failed; fetch/build the locked target dependencies first.\n" + result.stderr.strip())
    text, count = render_notices(json.loads(result.stdout), project_root, args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=args.output.parent, delete=False) as output:
        temporary_path = Path(output.name)
        output.write(text)
    try:
        temporary_path.replace(args.output)
    finally:
        temporary_path.unlink(missing_ok=True)
    print("Generated notices for " + str(count) + " packages: " + str(args.output), file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
