"""Build and package WorkflowFence native previews with fixed archive metadata."""
from argparse import ArgumentParser
import gzip
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import subprocess
import tarfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0-preview"
PLATFORMS = (
    ("linux", "amd64", "linux-x64"),
    ("darwin", "arm64", "macos-arm64"),
    ("windows", "amd64", "windows-x64"),
)


def content(name):
    return (ROOT / name).read_bytes().replace(b"\r\n", b"\n")


def archive_files(path, entries):
    if path.suffix == ".zip":
        with ZipFile(path, "w") as output:
            for name, (data, mode) in sorted(entries.items()):
                info = ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                output.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)
    else:
        with path.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as output:
                for name, (data, mode) in sorted(entries.items()):
                    info = tarfile.TarInfo(name)
                    info.mode, info.size = mode, len(data)
                    output.addfile(info, BytesIO(data))


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable")
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    dist = args.dist.resolve()
    dist.mkdir(parents=True, exist_ok=True)
    bin_dir = dist / "build"
    bin_dir.mkdir(exist_ok=True)
    docs = ["LICENSE", "README.md", "assets/banner.svg",
            "third_party/yaml-v3/LICENSE", "third_party/yaml-v3/NOTICE"]
    docs.extend(path.relative_to(ROOT).as_posix() for path in (ROOT / "examples").rglob("*.yml"))
    common = {name: (content(name), 0o644) for name in docs}

    rows = []
    for os_name, architecture, target in PLATFORMS:
        windows = os_name == "windows"
        executable = "workflowfence.exe" if windows else "workflowfence"
        binary = bin_dir / (target + "-" + executable)
        env = {**os.environ, "GOOS": os_name, "GOARCH": architecture, "CGO_ENABLED": "0"}
        subprocess.run([args.go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                        "-ldflags=-s -w", "-o", binary, "./cmd/workflowfence"],
                       env=env, cwd=ROOT, check=True)
        suffix = ".zip" if windows else ".tar.gz"
        output = dist / f"workflowfence-{VERSION}-{target}{suffix}"
        archive_files(output, {**common, f"bin/{executable}": (binary.read_bytes(), 0o755)})
        rows.append((output.name, sha256(output.read_bytes()).hexdigest()))
    (dist / "SHA256SUMS.txt").write_bytes("".join(
        f"{digest}  {name}\n" for name, digest in sorted(rows)).encode("ascii"))


if __name__ == "__main__":
    main()
