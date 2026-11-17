#!/usr/bin/env python3
"""Build local Linux relay archives without publishing or deploying them."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--output", type=Path, default=root / "dist")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="quri-package-", dir=output)).resolve()
    if not stage.is_relative_to(output):
        raise RuntimeError("staging directory escaped output directory")
    environment = dict(os.environ, GOOS="linux", GOARCH=args.arch, CGO_ENABLED="0", GOWORK="off")
    try:
        for name, directory, package in (
            ("quri", root, "./cmd/quri"),
            ("quri-relay", root / "mirayintegration", "./cmd/quri-relay"),
        ):
            subprocess.run(["go", "build", "-trimpath", "-o", str(stage / name), package], cwd=directory, env=environment, check=True)
        for name in ("install.sh", "server.example.json"):
            shutil.copyfile(root / "deploy" / name, stage / name)
        core = root.parent / "miray"
        shutil.copyfile(core / "LICENSE", stage / "LICENSE.miray")
        version = subprocess.check_output(["go", "version", "-m", str(stage / "quri-relay")], cwd=root, text=True)
        (stage / "BUILDINFO.txt").write_text(version, encoding="utf-8", newline="\n")
        archive = output / f"quri-relay-linux-{args.arch}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for path in sorted(stage.iterdir()):
                info = bundle.gettarinfo(str(path), arcname=path.name)
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o755 if path.name in ("quri", "quri-relay", "install.sh") else 0o644
                with path.open("rb") as source:
                    bundle.addfile(info, source)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        print(archive)
    finally:
        if not stage.is_relative_to(output):
            raise RuntimeError("refusing cleanup outside output directory")
        shutil.rmtree(stage)


if __name__ == "__main__":
    main()
