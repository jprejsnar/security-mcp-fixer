"""Find installed packages and apply the smallest manifest edit."""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from gitlab_security_mcp.util import atomic_write_text, json_object, resolve_inside
from gitlab_security_mcp.versions import bump_npm_spec, parse_version, range_allows

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    ".pnpm-store",
    ".angular",
    ".gradle",
    "bin",
    "obj",
    "target",
    "dist",
    "build",
    ".security-mcp",
    "__pycache__",
}
MAX_FILES = 5000
DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


@dataclass
class PackageHit:
    """Describe a located package and its manifest or lockfile evidence."""

    ecosystem: str
    manager: str
    name: str
    version: str | None
    spec: str | None
    manifest: str | None
    lockfile: str | None
    direct: bool | None
    search_truncated: bool = False
    override_manifest: str | None = None
    configuration_versions: dict[str, list[str]] | None = None


@dataclass
class GradleReport:
    """Index selected coordinates by project/configuration without retaining raw output."""

    versions: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    unresolved: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


@dataclass
class StackInfo:
    """Describe detected build stacks, frameworks, and configuration files."""

    node: bool = False
    node_manager: str | None = None
    dotnet: bool = False
    target_frameworks: list[str] | None = None
    java: bool = False
    java_build: str | None = None
    java_builds: list[str] | None = None
    nginx_configs: list[str] | None = None
    dockerfiles: list[str] | None = None
    lockfiles: dict[str, str] | None = None


def _rel(root: Path, path: Path) -> str:
    """Return normalized relative paths after resolving repository files."""
    return path.resolve().relative_to(root.resolve()).as_posix()


def iter_files(root: Path) -> tuple[list[Path], bool]:
    """Walk the repo, pruning dependency and build directories in place.

    ``os.walk`` is used so ``node_modules`` is not descended into. A recursive
    glob would still open every file under those trees before filtering.
    Raise OSError on unreadable directories rather than proving absence
    from an incomplete walk.
    """

    def fail_walk(error: OSError) -> None:
        """Propagate filesystem errors into the caller's evidence boundary."""
        raise error

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=fail_walk):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            # A symlink can sit inside the tree and point outside it.
            if path.is_symlink() and resolve_inside(root, path) is None:
                continue
            found.append(path)
            if len(found) > MAX_FILES:
                return found, True
    return found, False


def detect_stack(root: Path, files: list[Path] | None = None) -> StackInfo:
    """Detect Node, .NET, Java, NGINX, and Docker files from one file list."""
    if files is None:
        files, _truncated = iter_files(root)
    info = StackInfo(
        target_frameworks=[],
        nginx_configs=[],
        dockerfiles=[],
        lockfiles={},
        java_builds=[],
    )
    for path in files:
        name = path.name.lower()
        rel = _rel(root, path)
        if name == "package.json":
            info.node = True
        elif name == "pnpm-lock.yaml":
            info.lockfiles["pnpm"] = rel
        elif name == "yarn.lock":
            info.lockfiles["yarn"] = rel
        elif name == "package-lock.json":
            info.lockfiles["npm"] = rel
        elif name == "packages.lock.json" or name.endswith(
            (".csproj", ".fsproj", ".vbproj", ".sln", ".slnx")
        ):
            info.dotnet = True
            if name.endswith((".csproj", ".fsproj", ".vbproj")):
                info.target_frameworks.extend(
                    _target_frameworks(
                        path.read_text(encoding="utf-8", errors="replace")
                    )
                )
        elif name == "pom.xml":
            info.java = True
            if "maven" not in info.java_builds:
                info.java_builds.append("maven")
        elif name in {
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "libs.versions.toml",
        }:
            info.java = True
            if "gradle" not in info.java_builds:
                info.java_builds.append("gradle")
        elif name == "nginx.conf" or name.endswith(".nginx"):
            info.nginx_configs.append(rel)
        elif name == "dockerfile" or name.endswith(".dockerfile"):
            info.dockerfiles.append(rel)
    if info.node:
        package_json = _read_json(root / "package.json") or {}
        declared = str(package_json.get("packageManager") or "")
        if declared.startswith("pnpm") or "pnpm" in info.lockfiles:
            info.node_manager = "pnpm"
        elif declared.startswith("yarn") or (
            "yarn" in info.lockfiles and "npm" not in info.lockfiles
        ):
            info.node_manager = "yarn"
        else:
            info.node_manager = "npm"
    if info.java_builds:
        # A Gradle file used to hide a Maven build. Keep the last tool as the
        # single-build label and retain every detected build for validation.
        info.java_build = info.java_builds[-1]
    return info


def java_build_roots(
    root: Path, manager: str, files: list[Path] | None = None
) -> list[Path]:
    """Find independent Java builds without repeating declared reactor modules."""
    if files is None:
        files, truncated = iter_files(root)
        if truncated:
            raise ValueError(
                "Java build discovery was truncated; manual review is required"
            )
    if manager == "gradle":
        settings = {
            path.parent
            for path in files
            if path.name in {"settings.gradle", "settings.gradle.kts"}
        }
        directories = (
            settings
            | {
                path.parent
                for path in files
                if path.name in {"build.gradle", "build.gradle.kts"}
            }
            | {
                path.parent.parent if path.parent.name == "gradle" else path.parent
                for path in files
                if path.name == "libs.versions.toml"
            }
        )
        return sorted(
            {
                next(
                    (
                        parent
                        for parent in (directory, *directory.parents)
                        if parent in settings
                    ),
                    directory,
                )
                for directory in directories
            }
        )
    if manager != "maven":
        raise ValueError(f"Unknown Java build manager: {manager}")
    poms = {path.resolve() for path in files if path.name == "pom.xml"}
    included = set()
    members: dict[Path, set[Path]] = {}
    for path in poms:
        members[path] = set()
        try:
            project = ET.parse(path).getroot()
        except ET.ParseError as exc:
            raise ValueError(f"Could not parse {path}") from exc
        for modules in project:
            if _local(modules.tag) != "modules":
                continue
            for module in modules:
                if _local(module.tag) != "module" or not module.text:
                    continue
                directory = resolve_inside(root, path.parent / module.text.strip())
                if directory is None:
                    raise ValueError("Maven module must stay inside the repository")
                pom = (
                    directory if directory.name == "pom.xml" else directory / "pom.xml"
                )
                if pom in poms:
                    included.add(pom)
                    members[path].add(pom)
    roots = sorted(path.parent for path in poms - included)
    pending = list(poms - included)
    visited = set()
    while pending:
        path = pending.pop()
        if path not in visited:
            visited.add(path)
            pending.extend(members[path] - visited)
    if poms - visited:
        raise ValueError("Maven reactor modules contain a cycle")
    return roots


def java_project_root(
    root: Path, manifest: str | Path, manager: str, files: list[Path] | None = None
) -> Path:
    """Resolve a manifest or catalog to its owning Java build."""
    path = resolve_inside(root, manifest)
    if path is None:
        raise ValueError("Java project must stay inside the repository")
    candidates = [
        directory
        for directory in java_build_roots(root, manager, files)
        if path.is_relative_to(directory)
    ]
    if candidates:
        return max(candidates, key=lambda directory: len(directory.parts))
    if path.name == "libs.versions.toml" and path.parent.name == "gradle":
        return path.parent.parent
    return path.parent


def is_modern_yarn(root: Path) -> bool:
    """Distinguish Yarn Berry from Classic using declared or lockfile metadata."""
    declared = (_read_json(root / "package.json") or {}).get("packageManager", "")
    match = re.match(r"yarn@(\d+)(?:\.|$)", str(declared))
    if match:
        return int(match.group(1)) >= 2
    lock = root / "yarn.lock"
    return lock.exists() and bool(
        re.search(r"^__metadata:", lock.read_text(encoding="utf-8"), re.MULTILINE)
    )


def _target_frameworks(text: str) -> list[str]:
    """Split single or multitarget .NET framework declarations."""
    values = re.findall(
        r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", text, flags=re.IGNORECASE
    )
    return [
        framework.strip()
        for value in values
        for framework in value.split(";")
        if framework.strip()
    ]


def _read_json(path: Path) -> dict | None:
    """Read object-shaped metadata, returning None only for absent files.

    Validate known dependency and manager mappings. Read, decoding, and
    shape errors propagate so callers cannot infer safe package absence.
    """
    if not path.exists():
        return None
    data = json_object(path.read_text(encoding="utf-8"))
    for key in (
        *DEPENDENCY_SECTIONS,
        "packages",
        "scripts",
        "pnpm",
        "overrides",
        "resolutions",
    ):
        if key in data and not isinstance(data[key], dict):
            raise ValueError(f"{path}: {key} must be a JSON object")
    pnpm = data.get("pnpm", {})
    if "overrides" in pnpm and not isinstance(pnpm["overrides"], dict):
        raise ValueError(f"{path}: pnpm overrides must be a JSON object")
    return data


def _package_json_spec(data: dict, name: str) -> tuple[str | None, bool]:
    """Find a string dependency spec and report whether it is direct."""
    for section in DEPENDENCY_SECTIONS:
        specs = data.get(section) or {}
        if isinstance(specs, dict) and name in specs and isinstance(specs[name], str):
            return specs[name], True
    return None, False


def _npm_lock_versions(data: dict, name: str) -> list[str]:
    """Read resolved versions from current and legacy npm lock layouts."""
    versions: list[str] = []
    packages = data.get("packages") or {}
    needle = f"node_modules/{name}"
    for key, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        if key == needle or key.endswith("/" + needle):
            version = meta.get("version")
            if isinstance(version, str):
                versions.append(version)
    legacy = (data.get("dependencies") or {}).get(name) or {}
    if isinstance(legacy, dict) and isinstance(legacy.get("version"), str):
        versions.append(legacy["version"])
    return versions


def _yarn_versions(text: str, name: str) -> list[str]:
    # Yarn 1 keys may be quoted ("a@^1", "a@^1.2":) and Yarn 2+ writes
    # "version: 1.2.3" without quotes.
    pattern = re.compile(
        rf"^\"?{re.escape(name)}@[^\n]*:\r?\n(?:[ \t].*\r?\n)*?[ \t]+version:? \"?([^\"\s]+)\"?",
        re.MULTILINE,
    )
    return pattern.findall(text)


def _pnpm_versions(text: str, name: str) -> list[str]:
    # pnpm 6-8 keys look like "  /lodash@4.17.20:" and pnpm 9 like
    # "  lodash@4.17.20:". Anchoring on indentation keeps "@scope/lodash"
    # from matching "lodash".
    pattern = re.compile(
        rf"^[ \t]*['\"]?/?{re.escape(name)}@([0-9][^:\s'\"(]*)",
        re.MULTILINE,
    )
    return pattern.findall(text)


def _prefer(versions: list[str], hinted: str | None) -> str | None:
    """Prefer a matching scanner hint, otherwise the lowest parsed version."""
    if hinted and hinted in versions:
        return hinted
    parsed = [(parse_version(item), item) for item in versions]
    usable = [(version, raw) for version, raw in parsed if version is not None]
    if not usable:
        return versions[0] if versions else None
    usable.sort(key=lambda item: item[0])
    return usable[0][1]


def locate_npm(
    root: Path, name: str, hinted: str | None, files: list[Path]
) -> PackageHit | None:
    """Locate Node dependencies within each manifest/lockfile component."""
    components = sorted(
        {
            path.parent
            for path in files
            if path.name
            in {"package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"}
        }
    )
    hits = []
    for component in components:
        component_files = [path for path in files if path.parent == component]
        hit = _locate_npm_component(component, name, hinted, component_files)
        if hit is None:
            continue
        if hit.manifest:
            hit.manifest = _rel(root, component / hit.manifest)
        if hit.lockfile:
            hit.lockfile = _rel(root, component / hit.lockfile)
        if hit.override_manifest:
            hit.override_manifest = _rel(root, component / hit.override_manifest)
        hits.append(hit)
    for hit in hits:
        if not hit.direct or hit.lockfile or not hit.manifest:
            continue
        owners = [
            candidate
            for candidate in hits
            if candidate.lockfile
            and Path(hit.manifest).parent.is_relative_to(
                Path(candidate.lockfile).parent
            )
        ]
        if owners:
            owner = max(
                owners, key=lambda candidate: len(Path(candidate.lockfile).parts)
            )
            hit.lockfile = owner.lockfile
            hit.version = owner.version
            hit.manager = owner.manager
            hit.override_manifest = owner.override_manifest
    if hinted:
        matched = [hit for hit in hits if hit.version == hinted]
        if matched:
            return next((hit for hit in matched if hit.direct), matched[0])
    return next((hit for hit in hits if hit.direct), hits[0] if hits else None)


def _locate_npm_component(
    root: Path, name: str, hinted: str | None, files: list[Path]
) -> PackageHit | None:
    """Keep dependency specifications and lock evidence in one component."""
    manifests = [path for path in files if path.name == "package.json"]
    spec = None
    manifest = "package.json" if manifests else None
    direct = False
    for path in manifests:
        data = _read_json(path)
        if not data:
            continue
        found, is_direct = _package_json_spec(data, name)
        if is_direct:
            spec = found
            manifest = _rel(root, path)
            direct = True
            break
    lock_versions: list[str] = []
    lock_rel = None
    manager = detect_stack(root, files).node_manager
    if manager is None:
        manager = (
            "pnpm"
            if (root / "pnpm-lock.yaml").is_file()
            else "yarn"
            if (root / "yarn.lock").is_file()
            else "npm"
        )
    if manager == "pnpm":
        lock = root / "pnpm-lock.yaml"
        if lock.exists():
            lock_versions = _pnpm_versions(
                lock.read_text(encoding="utf-8", errors="replace"), name
            )
            lock_rel = "pnpm-lock.yaml"
    elif manager == "yarn":
        lock = root / "yarn.lock"
        if lock.exists():
            lock_versions = _yarn_versions(
                lock.read_text(encoding="utf-8", errors="replace"), name
            )
            lock_rel = "yarn.lock"
    else:
        lock = root / "package-lock.json"
        data = _read_json(lock)
        if data:
            lock_versions = _npm_lock_versions(data, name)
            lock_rel = "package-lock.json"
    if not direct and not lock_versions:
        return None
    return PackageHit(
        ecosystem="npm",
        manager=manager,
        name=name,
        version=_prefer(lock_versions, hinted)
        or (spec if spec and parse_version(spec) else None),
        spec=spec,
        manifest=manifest,
        lockfile=lock_rel,
        direct=direct,
        override_manifest="pnpm-workspace.yaml" if manager == "pnpm" else None,
    )


def _local(tag: str) -> str:
    """Strip an XML namespace so Maven tags can be compared by local name."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _pom_dependencies(path: Path) -> list[dict[str, str]]:
    """Read Maven dependency fields; reject malformed XML as unreadable."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse {path}") from exc
    found: list[dict[str, str]] = []
    for node in root.iter():
        if _local(node.tag) != "dependency":
            continue
        item: dict[str, str] = {}
        for child in list(node):
            item[_local(child.tag)] = (child.text or "").strip()
        if item.get("artifactId"):
            found.append(item)
    return found


def _pom_properties(path: Path) -> dict[str, str]:
    """Read local Maven properties used to resolve dependency versions."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse {path}") from exc
    props: dict[str, str] = {}
    for node in root.iter():
        if _local(node.tag) != "properties":
            continue
        for child in list(node):
            props[_local(child.tag)] = (child.text or "").strip()
    return props


def locate_maven(
    root: Path, name: str, hinted: str | None, files: list[Path]
) -> PackageHit | None:
    """Locate a Maven dependency, resolving version properties when available."""
    group, artifact = _split_maven_name(name)
    for path in files:
        if path.name != "pom.xml":
            continue
        for dep in _pom_dependencies(path):
            if dep.get("artifactId") != artifact:
                continue
            if group and dep.get("groupId") and dep.get("groupId") != group:
                continue
            version = dep.get("version")
            prop = None
            if version and version.startswith("${") and version.endswith("}"):
                prop = version[2:-1]
                version = _pom_properties(path).get(prop)
            coordinate = f"{dep.get('groupId', group or '')}:{dep.get('artifactId')}"
            return PackageHit(
                ecosystem="Maven",
                manager="maven",
                name=coordinate.strip(":"),
                version=version or hinted,
                spec=version,
                manifest=_rel(root, path),
                lockfile=None,
                direct=True,
            )
    return None


def _split_maven_name(name: str) -> tuple[str | None, str | None]:
    """Separate group and artifact when a full Maven coordinate is present."""
    if ":" in name:
        group, artifact = name.split(":", 1)
        return group, artifact
    if name.count("/") == 1 and not name.startswith("@"):
        group, artifact = name.split("/", 1)
        if group and artifact:
            return group, artifact
    return None, name


def locate_gradle(root: Path, name: str, files: list[Path]) -> PackageHit | None:
    """Locate a Gradle coordinate in build files or a version catalog."""
    group, artifact = _split_maven_name(name)
    coordinate = f"{group}:{artifact}" if group else None
    patterns = []
    if coordinate:
        patterns.append(
            re.compile(rf"""['\"]{re.escape(coordinate)}:([^'\"\s]+)['\"]""")
        )
    for path in files:
        if path.name not in {"build.gradle", "build.gradle.kts"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return PackageHit(
                    ecosystem="Maven",
                    manager="gradle",
                    name=coordinate or name,
                    version=match.group(1),
                    spec=match.group(1),
                    manifest=_rel(root, path),
                    lockfile=None,
                    direct=True,
                )
        mapped = _gradle_map_version(text, coordinate or "")
        if mapped:
            return PackageHit(
                ecosystem="Maven",
                manager="gradle",
                name=coordinate or name,
                version=mapped,
                spec=mapped,
                manifest=_rel(root, path),
                lockfile=None,
                direct=True,
            )
        if not coordinate:
            plugin_version = _plugin_version(text, name)
            if plugin_version:
                return _gradle_hit(root, path, name, plugin_version)
    if coordinate:
        for path in files:
            if path.name != "libs.versions.toml":
                continue
            hit = _toml_library_version(path, coordinate)
            if hit:
                return PackageHit(
                    ecosystem="Maven",
                    manager="gradle",
                    name=coordinate,
                    version=hit[0],
                    spec=hit[0],
                    manifest=_rel(root, path),
                    lockfile=None,
                    direct=True,
                )
    if not coordinate:
        for path in files:
            if path.name not in {"settings.gradle", "settings.gradle.kts"}:
                continue
            plugin_version = _plugin_version(
                path.read_text(encoding="utf-8", errors="replace"), name
            )
            if plugin_version:
                return _gradle_hit(root, path, name, plugin_version)
        for path in files:
            if path.name != "libs.versions.toml":
                continue
            hit = _toml_plugin_version(path, name)
            if hit:
                return _gradle_hit(root, path, name, hit[0])
    return None


def _gradle_hit(root: Path, path: Path, name: str, version: str) -> PackageHit:
    """Return a direct Gradle hit for one coordinate or plugin id."""
    return PackageHit(
        ecosystem="Maven",
        manager="gradle",
        name=name,
        version=version,
        spec=version,
        manifest=_rel(root, path),
        lockfile=None,
        direct=True,
    )


def parse_gradle_report(report: str) -> GradleReport:
    """Index actual selections once, preserving independent Gradle classpaths."""
    parsed = GradleReport()
    task = re.compile(r"^> Task ((?::[\w.-]+)*):dependencies(?:\s|$)")
    header = re.compile(r"^([A-Za-z][\w.-]*)(?: - .*)?(?: \(n\))?$")
    dependency = re.compile(r"^[ |+\\-]+([^:\s]+:[^:\s]+)(?::|\s+->\s+)(.+)$")
    arrow = re.compile(r"\s+->\s+")
    project, configuration, resolvable = "", "unscoped", True
    for line in report.splitlines():
        if line.startswith("Deprecated Gradle features were used"):
            warning = line.strip()[:500]
            if warning not in parsed.warnings:
                parsed.warnings.append(warning)
            continue
        if match := task.match(line):
            project, configuration, resolvable = match.group(1), "unscoped", True
            continue
        if match := header.fullmatch(line):
            configuration, resolvable = match.group(1), not line.endswith("(n)")
            continue
        match = dependency.match(line)
        if match is None or not resolvable:
            continue
        coordinate, selection = match.groups()
        if "(c)" in selection or "(n)" in selection:
            continue
        version = arrow.split(selection, maxsplit=1)[-1].split()[0]
        if "FAILED" in selection or parse_version(version) is None:
            parsed.unresolved.add(coordinate)
            continue
        scope = f"{project}:{configuration}" if project else configuration
        parsed.versions.setdefault(coordinate, {}).setdefault(scope, set()).add(version)
    return parsed


def gradle_report_package(
    root: Path,
    manifest: Path,
    name: str,
    report: str | GradleReport,
    *,
    hinted: str | None = None,
) -> PackageHit | None:
    """Match observed scanner versions without merging independent classpaths."""
    group, artifact = _split_maven_name(name)
    if not group or not artifact:
        return None
    coordinate = f"{group}:{artifact}"
    parsed = parse_gradle_report(report) if isinstance(report, str) else report
    if coordinate in parsed.unresolved:
        raise ValueError(f"Gradle did not resolve a concrete version of {coordinate}")
    configurations = parsed.versions.get(coordinate) or {}
    if any(len(versions) > 1 for versions in configurations.values()):
        raise ValueError(
            f"Gradle selected conflicting versions of {coordinate} within a configuration"
        )
    versions = {version for selected in configurations.values() for version in selected}
    if not configurations:
        return None
    if len(versions) > 1 and hinted not in versions:
        raise ValueError(
            f"Gradle selected multiple configuration versions of {coordinate}; scanner version {hinted or 'unknown'} was not observed"
        )
    version = hinted if hinted in versions else next(iter(versions))
    return PackageHit(
        ecosystem="Maven",
        manager="gradle",
        name=coordinate,
        version=version,
        spec=None,
        manifest=_rel(root, manifest),
        lockfile=None,
        direct=False,
        configuration_versions={
            scope: sorted(selected) for scope, selected in configurations.items()
        },
    )


def _toml_library_version(path: Path, coordinate: str) -> tuple[str, str] | None:
    """Resolve supported inline or referenced Gradle catalog versions."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Could not parse {path}") from exc
    versions = data.get("versions") or {}
    libraries = data.get("libraries") or {}
    if not isinstance(versions, dict) or not isinstance(libraries, dict):
        raise ValueError(f"{path}: versions and libraries must be TOML tables")
    for library in libraries.values():
        if not isinstance(library, dict):
            continue
        module = library.get("module")
        if module is None and library.get("group") and library.get("name"):
            module = f"{library['group']}:{library['name']}"
        if module != coordinate:
            continue
        if isinstance(library.get("version"), str):
            return library["version"], "inline"
        ref = (
            (library.get("version") or {}).get("ref")
            if isinstance(library.get("version"), dict)
            else None
        )
        if ref and ref in versions:
            return str(versions[ref]), str(ref)
    return None


def _nested_nuget(name: str) -> str:
    r"""Match ``<PackageReference Include="x"><Version>`` inside one element only.

    A plain lazy ``[\s\S]*?`` would run past ``</PackageReference>`` and
    pick up the next package's version.
    """
    return (
        rf'(<PackageReference\s+Include="{re.escape(name)}"\s*>'
        r"(?:(?!</PackageReference>)[\s\S])*?<Version>)([^<]+)(</Version>)"
    )


def locate_nuget(root: Path, name: str, files: list[Path]) -> PackageHit | None:
    """Locate a NuGet reference in project or central package metadata."""
    pattern = re.compile(
        rf'<PackageReference\s+Include="{re.escape(name)}"\s+Version="([^"]+)"',
        re.IGNORECASE,
    )
    nested = re.compile(_nested_nuget(name), re.IGNORECASE)
    central = re.compile(
        rf'<PackageVersion\s+Include="{re.escape(name)}"\s+Version="([^"]+)"',
        re.IGNORECASE,
    )
    for path in files:
        if (
            path.suffix.lower() not in {".csproj", ".fsproj", ".vbproj"}
            and path.name != "Directory.Packages.props"
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        nested_match = nested.search(text)
        found = None
        if match := pattern.search(text):
            found = match.group(1)
        elif nested_match:
            found = nested_match.group(2)
        elif match := central.search(text):
            found = match.group(1)
        if found:
            lock = path.parent / "packages.lock.json"
            return PackageHit(
                ecosystem="NuGet",
                manager="nuget",
                name=name,
                version=found.strip(),
                spec=found.strip(),
                manifest=_rel(root, path),
                lockfile=_rel(root, lock) if lock.exists() else None,
                direct=True,
            )
    return None


def locate_nuget_lock(root: Path, name: str, files: list[Path]) -> PackageHit | None:
    """Locate a resolved NuGet dependency in a packages.lock.json file."""
    for path in files:
        if path.name != "packages.lock.json":
            continue
        data = _read_json(path)
        if not data:
            continue
        for deps in (data.get("dependencies") or {}).values():
            if not isinstance(deps, dict):
                continue
            for dep_name, meta in deps.items():
                if dep_name.lower() != name.lower() or not isinstance(meta, dict):
                    continue
                return PackageHit(
                    ecosystem="NuGet",
                    manager="nuget",
                    name=dep_name,
                    version=meta.get("resolved"),
                    spec=None,
                    manifest=None,
                    lockfile=_rel(root, path),
                    direct=False,
                )
    return None


def locate_package(
    root: Path,
    name: str | None,
    hinted_version: str | None = None,
    files: list[Path] | None = None,
    truncated: bool | None = None,
) -> tuple[PackageHit | None, bool]:
    """Find one package in manifests and lockfiles.

    Pass a previously built ``files`` list to avoid walking the tree again
    for every finding.
    """
    if not name:
        return None, False
    if files is None:
        files, truncated = iter_files(root)
    elif truncated is None:
        truncated = False
    hit = (
        locate_npm(root, name, hinted_version, files)
        or locate_nuget(root, name, files)
        or locate_nuget_lock(root, name, files)
        or locate_maven(root, name, hinted_version, files)
        or locate_gradle(root, name, files)
    )
    search_truncated = bool(truncated)
    if hit is not None:
        hit.search_truncated = search_truncated
    return hit, search_truncated


def manifests_were_parsed(root: Path, files: list[Path] | None = None) -> bool:
    """Return whether this tree has a manifest we know how to parse."""
    if files is None:
        files, _truncated = iter_files(root)
    names = {path.name for path in files}
    return bool(
        names
        & {
            "package.json",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "Directory.Packages.props",
        }
    ) or any(path.suffix.lower() in {".csproj", ".fsproj"} for path in files)


def _destination(root: Path, relative: str) -> Path:
    """Resolve a repo-relative path and refuse anything that escapes the root."""
    resolved = resolve_inside(root, relative)
    if resolved is None:
        raise ValueError(f"Refusing to write outside the repository: {relative}")
    return resolved


def _read(path: Path) -> str:
    """Read text without translating line endings, so a write keeps CRLF files CRLF."""
    with path.open(encoding="utf-8", newline="") as stream:
        return stream.read()


def _write(path: Path, text: str) -> None:
    """Write text exactly as given. No newline translation."""
    atomic_write_text(path, text)


def _replace_groups(match: re.Match[str], value: str) -> str:
    """Keep groups 1 and the last group and put ``value`` between them.

    A function replacement is used so a value with a backslash cannot be
    read as a regex group reference.
    """
    return match.group(1) + value + match.group(match.re.groups)


def update_npm_spec(root: Path, manifest: str, package: str, new_spec: str) -> bool:
    """Replace one dependency spec without rewriting the rest of the file."""
    path = _destination(root, manifest)
    text = _read(path)
    data = json_object(text)
    old = None
    for section in DEPENDENCY_SECTIONS:
        specs = data.get(section) or {}
        if isinstance(specs, dict) and package in specs:
            old = specs[package]
            break
    if not isinstance(old, str):
        return False
    pattern = re.compile(rf'("{re.escape(package)}"\s*:\s*"){re.escape(old)}(")')
    updated, count = pattern.subn(
        lambda match: _replace_groups(match, new_spec), text, count=1
    )
    if count != 1:
        return False
    _write(path, updated)
    return True


def _json_layout(text: str) -> tuple[str | int, str]:
    """Return the indent and newline style a JSON file already uses."""
    newline = "\r\n" if "\r\n" in text else "\n"
    match = re.search(r"\n([ \t]+)\S", text)
    if match is None:
        return 2, newline
    indent = match.group(1)
    return (indent if "\t" in indent else len(indent)), newline


def add_npm_override(
    root: Path, package: str, version: str, manager: str, manifest: str = "package.json"
) -> str:
    """Pin a transitive package with npm overrides, pnpm overrides, or yarn resolutions.

    The file is rewritten as JSON, keeping its indent, line endings, and
    non-ASCII text, so the diff is the new override block.
    """
    if manager == "pnpm" and Path(manifest).name == "package.json":
        manifest = (Path(manifest).parent / "pnpm-workspace.yaml").as_posix()
    path = _destination(root, manifest)
    text = "" if manager == "pnpm" and not path.exists() else _read(path)
    if manager == "pnpm" and path.name == "pnpm-workspace.yaml":
        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.line_break = "\r\n" if "\r\n" in text else "\n"
        try:
            data = yaml.load(text) if text.strip() else {}
            if not isinstance(data, dict):
                raise ValueError("pnpm-workspace.yaml must contain a mapping")
            overrides = data.setdefault("overrides", {})
            if not isinstance(overrides, dict):
                raise ValueError("pnpm workspace overrides must contain a mapping")
            package_data = _read_json(path.parent / "package.json") or {}
            legacy = (package_data.get("pnpm") or {}).get("overrides") or {}
            if not isinstance(legacy, dict):
                raise ValueError("Legacy pnpm overrides must contain a mapping")
            for name, value in legacy.items():
                if name != package and name in overrides and overrides[name] != value:
                    raise ValueError(
                        "Conflicting legacy/workspace pnpm overrides require review"
                    )
                overrides.setdefault(name, value)
            overrides[package] = version
            with StringIO() as stream:
                yaml.dump(data, stream)
                rendered = stream.getvalue()
        except YAMLError as exc:
            raise ValueError("Could not parse pnpm-workspace.yaml safely") from exc
        _write(path, rendered)
        return manifest
    data = _read_json(path)
    if manager == "pnpm":
        data.setdefault("pnpm", {}).setdefault("overrides", {})[package] = version
    elif manager == "yarn":
        data.setdefault("resolutions", {})[package] = version
    else:
        data.setdefault("overrides", {})[package] = version
    indent, newline = _json_layout(text)
    rendered = json.dumps(data, indent=indent, ensure_ascii=False) + "\n"
    _write(path, rendered.replace("\n", newline))
    return manifest


def update_csproj_version(
    root: Path, manifest: str, package: str, version: str
) -> bool:
    """Bump one PackageReference or PackageVersion attribute."""
    path = _destination(root, manifest)
    text = _read(path)
    patterns = [
        re.compile(
            rf'(<PackageReference\s+Include="{re.escape(package)}"\s+Version=")[^"]+(")',
            re.IGNORECASE,
        ),
        re.compile(_nested_nuget(package), re.IGNORECASE),
        re.compile(
            rf'(<PackageVersion\s+Include="{re.escape(package)}"\s+Version=")[^"]+(")',
            re.IGNORECASE,
        ),
    ]
    for pattern in patterns:
        updated, count = pattern.subn(
            lambda match: _replace_groups(match, version), text, count=1
        )
        if count == 1:
            _write(path, updated)
            return True
    return False


_NUGET_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")


def add_nuget_reference(
    root: Path, package: str, version: str, files: list[Path] | None = None
) -> str | None:
    """Add a direct PackageReference when the repo has exactly one project."""
    # Both values land inside an XML attribute, so they are checked rather
    # than escaped: a valid NuGet id or version never needs escaping.
    if not _NUGET_ID.fullmatch(package) or not re.fullmatch(
        r"[0-9A-Za-z.+-]{1,64}", version
    ):
        return None
    if files is None:
        files, _truncated = iter_files(root)
    projects = [path for path in files if path.suffix.lower() == ".csproj"]
    if len(projects) != 1:
        return None
    path = projects[0]
    text = _read(path)
    newline = "\r\n" if "\r\n" in text else "\n"
    reference = f'<PackageReference Include="{package}" Version="{version}" />'
    updated, count = re.subn(
        r"^([ \t]*)</ItemGroup>",
        lambda match: (
            f"{match.group(1)}  {reference}{newline}{match.group(1)}</ItemGroup>"
        ),
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        return None
    _write(path, updated)
    return _rel(root, path)


def add_java_override(
    root: Path,
    manifest: str,
    package: str,
    version: str,
    *,
    configurations: tuple[str, ...] = (),
) -> None:
    """Pin one resolved Java coordinate without changing the enclosing BOM."""
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+", package):
        raise ValueError("A Java override requires an exact group:artifact coordinate")
    path = _destination(root, manifest)
    text = _read(path)
    if path.name in {"build.gradle", "build.gradle.kts"}:
        key = _gradle_floor_key(package)
        properties = java_project_root(root, manifest, "gradle") / "gradle.properties"
        start, end = (
            f"// security-mcp:start {package}",
            f"// security-mcp:end {package}",
        )
        owned = re.compile(
            rf"(?m)^{re.escape(start)}\r?\n.*?^{re.escape(end)}[ \t]*$", re.DOTALL
        )
        matches = list(owned.finditer(text))
        existing = _read(properties) if properties.exists() else ""
        if len(matches) > 1 or (
            not matches and re.search(rf"(?m)^{re.escape(key)}[ \t]*=", existing)
        ):
            raise ValueError(
                "Ambiguous/existing Gradle security property requires review; it will not be overwritten"
            )
        block = (
            f"{start}\ndependencies {{\n    constraints {{\n"
            f'        add("implementation", "{package}") {{\n'
            f'            version {{ strictly(project.providers.gradleProperty("{key}").get()) }}\n'
            '            because("Reviewed security remediation; preserve the existing dependency graph.")\n'
            f"        }}\n    }}\n}}\n{end}"
        )
        if configurations:
            names = sorted({scope.rsplit(":", 1)[-1] for scope in configurations})
            if any(
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,100}", name) is None
                for name in names
            ):
                raise ValueError(
                    "A Gradle resolution override requires exact configuration names"
                )
            rules = "\n".join(
                f'configurations.named("{name}") {{\n'
                f'    resolutionStrategy.force("{package}:" + project.providers.gradleProperty("{key}").get())\n'
                "}"
                for name in names
            )
            block = f"{start}\n{rules}\n{end}"
        newline = "\r\n" if "\r\n" in text else "\n"
        block = block.replace("\n", newline)
        updated = (
            owned.sub(lambda _match: block, text, count=1)
            if matches
            else text.rstrip() + newline * 2 + block + newline
        )
        property_text = _gradle_property_text(existing, key, version)
        documentation = _gradle_version_documentation(
            root, key, version, _rel(root, properties)
        )
        _write(path, updated)
        _write(properties, property_text)
        if documentation is not None:
            _write(root / ".github" / "versions.md", documentation)
        return
    if path.name != "pom.xml":
        raise ValueError(
            "Java overrides require a build.gradle, build.gradle.kts or pom.xml"
        )
    group, artifact = package.split(":")
    entry = (
        "\n      <dependency>\n"
        f"        <groupId>{group}</groupId>\n"
        f"        <artifactId>{artifact}</artifactId>\n"
        f"        <version>{version}</version>\n"
        "      </dependency>\n"
    )
    management = list(
        re.finditer(
            r"<dependencyManagement>\s*.*?</dependencyManagement>", text, re.DOTALL
        )
    )
    # Ambiguous profile-specific management requires a narrower reviewed edit.
    if len(management) > 1 or re.search(r"<\w+:project\b|<profiles\b", text):
        raise ValueError(
            "Profile-specific or prefixed Maven dependency management requires review"
        )
    if management:
        match = management[0]
        body = match[0]
        for dependency in re.finditer(
            r"<dependency>\s*.*?</dependency>", body, re.DOTALL
        ):
            if re.search(
                rf"<groupId>\s*{re.escape(group)}\s*</groupId>", dependency[0]
            ) and re.search(
                rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>", dependency[0]
            ):
                raise ValueError(
                    "Existing managed coordinate requires its own version/property update"
                )
        if "</dependencies>" in body:
            replacement = body.replace(
                "</dependencies>", entry + "    </dependencies>", 1
            )
        else:
            replacement = body.replace(
                "</dependencyManagement>",
                (
                    "  <dependencies>"
                    + entry
                    + "    </dependencies>\n  </dependencyManagement>"
                ),
                1,
            )
        updated = text[: match.start()] + replacement + text[match.end() :]
    else:
        if text.count("</project>") != 1:
            raise ValueError("Maven project closing element is missing or ambiguous")
        updated = text.replace(
            "</project>",
            (
                "  <dependencyManagement>\n    <dependencies>"
                + entry
                + "    </dependencies>\n  </dependencyManagement>\n</project>"
            ),
            1,
        )
    ET.fromstring(updated)
    _write(path, updated)


def update_pom_version(root: Path, manifest: str, package: str, version: str) -> bool:
    """Bump one Maven dependency, or the property its version references."""
    path = _destination(root, manifest)
    text = _read(path)
    group, artifact = _split_maven_name(package)
    if not artifact:
        return False
    for match in re.finditer(
        r"<dependency>\s*.*?</dependency>", text, flags=re.IGNORECASE | re.DOTALL
    ):
        body = match.group(0)
        if not re.search(
            rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>",
            body,
            flags=re.IGNORECASE,
        ):
            continue
        if group and not re.search(
            rf"<groupId>\s*{re.escape(group)}\s*</groupId>", body, flags=re.IGNORECASE
        ):
            continue
        prop = re.search(r"<version>\s*\$\{([^}]+)\}\s*</version>", body)
        if prop:
            prop_name = prop.group(1)
            prop_pattern = re.compile(
                rf"(<(?:[A-Za-z0-9_.-]+:)?{re.escape(prop_name)}>\s*)[^<]+(\s*</(?:[A-Za-z0-9_.-]+:)?{re.escape(prop_name)}>)"
            )
            updated, count = prop_pattern.subn(
                lambda found: _replace_groups(found, version), text, count=1
            )
            if count != 1:
                return False
            _write(path, updated)
            return True
        version_pattern = re.compile(r"(<version>\s*)[^<$\s]+(\s*</version>)")
        replaced, count = version_pattern.subn(
            lambda found: _replace_groups(found, version), body, count=1
        )
        if count != 1:
            return False
        _write(path, text[: match.start()] + replaced + text[match.end() :])
        return True
    return False


def _gradle_floor_key(package: str) -> str:
    """Use a new explicit namespace rather than guessing an existing policy key."""
    return "securityMcp." + package.replace(":", ".") + ".version"


def _gradle_property_reference(root: Path, manifest: str, package: str) -> str | None:
    """Recognize only explicit Gradle-property interpolation for this coordinate."""
    text = _read(_destination(root, manifest))
    match = re.search(
        rf'"{re.escape(package)}:\$(?:\{{([A-Za-z_][\w.-]*)\}}|([A-Za-z_]\w*))"', text
    )
    return (match[1] or match[2]) if match else None


def gradle_version_files(
    root: Path, manifest: str, package: str, *, override: bool
) -> list[str]:
    """Declare every property/policy edit before human approval and backup."""
    files = [manifest]
    if not override and Path(manifest).name == "libs.versions.toml":
        hit = _toml_library_version(_destination(root, manifest), package)
        if (root / ".github" / "versions.md").is_file():
            if hit is None or hit[1] == "inline":
                raise ValueError(
                    "Central version policy requires an explicit catalog version.ref"
                )
            _gradle_version_documentation(root, hit[1], "0.0.0", manifest)
            files.append(".github/versions.md")
        return files
    key = (
        _gradle_floor_key(package)
        if override
        else _gradle_property_reference(root, manifest, package)
    )
    if key:
        properties = java_project_root(root, manifest, "gradle") / "gradle.properties"
        files.append(_rel(root, properties))
        if (root / ".github" / "versions.md").is_file():
            _gradle_version_documentation(root, key, "0.0.0", _rel(root, properties))
            files.append(".github/versions.md")
    elif (root / ".github" / "versions.md").is_file():
        raise ValueError(
            "Repository version policy requires an explicit property/catalog mapping; do not guess a new literal version pin"
        )
    return files


def _gradle_property_text(text: str, key: str, version: str) -> str:
    """Update an unambiguous exact property without changing other pins."""
    pattern = re.compile(rf"(?m)^([ \t]*{re.escape(key)}[ \t]*=[ \t]*)[^\r\n]*(\r?)$")
    if len(list(pattern.finditer(text))) > 1:
        raise ValueError("Duplicate Gradle version properties require review")
    if pattern.search(text):
        return pattern.sub(lambda match: match[1] + version + match[2], text, count=1)
    newline = "\r\n" if "\r\n" in text else "\n"
    return text.rstrip("\r\n") + newline + key + "=" + version + newline


def _gradle_version_documentation(
    root: Path, key: str, version: str, source: str
) -> str | None:
    """Update the matching central pin row, or add it to a recognized pins table."""
    path = root / ".github" / "versions.md"
    if not path.is_file():
        return None
    text = _read(path)
    lines = text.splitlines(keepends=True)
    matching = [
        index
        for index, line in enumerate(lines)
        if line.startswith("|") and line.split("|")[1].strip().strip("`") == key
    ]
    if len(matching) > 1:
        raise ValueError("Duplicate central version-policy rows require review")
    newline = "\r\n" if "\r\n" in text else "\n"
    row = f"| {key} | `{version}` | `{source}` |{newline}"
    if matching:
        lines[matching[0]] = row
        return "".join(lines)
    for index, line in enumerate(lines[:-1]):
        columns = [column.strip().casefold() for column in line.split("|")[1:-1]]
        if (
            len(columns) == 3
            and columns[1] in {"version", "value"}
            and columns[2] == "source"
            and re.fullmatch(r"[|\s:-]+", lines[index + 1])
        ):
            lines.insert(index + 2, row)
            return "".join(lines)
    raise ValueError(
        "Unrecognized .github/versions.md pins table; manual policy mapping is required"
    )


def update_gradle_version(
    root: Path, manifest: str, package: str, version: str
) -> bool:
    """Bump one Gradle coordinate or version-catalog entry."""
    path = _destination(root, manifest)
    if path.name == "libs.versions.toml":
        hit = _toml_library_version(path, package)
        documentation = None
        if (root / ".github" / "versions.md").is_file():
            if hit is None or hit[1] == "inline":
                raise ValueError(
                    "Central version policy requires an explicit catalog version.ref"
                )
            documentation = _gradle_version_documentation(
                root, hit[1], version, manifest
            )
        updated = _update_toml_version(path, package, version)
        if updated and documentation is not None:
            _write(root / ".github" / "versions.md", documentation)
        return updated
    if key := _gradle_property_reference(root, manifest, package):
        properties = java_project_root(root, manifest, "gradle") / "gradle.properties"
        if not properties.is_file() or not re.search(
            rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=", _read(properties)
        ):
            raise ValueError(
                "Referenced Gradle version property was not found; no replacement was guessed"
            )
        updated = _gradle_property_text(_read(properties), key, version)
        documentation = _gradle_version_documentation(
            root, key, version, _rel(root, properties)
        )
        _write(properties, updated)
        if documentation is not None:
            _write(root / ".github" / "versions.md", documentation)
        return True
    text = _read(path)
    pattern = re.compile(rf"""(['\"]{re.escape(package)}:)[^'\"\s]+(['\"])""")
    updated, count = pattern.subn(
        lambda match: _replace_groups(match, version), text, count=1
    )
    if count != 1:
        updated, count = _replace_gradle_map(text, package, version)
        if count != 1:
            updated, count = _replace_plugin(text, package, version)
        if count != 1:
            return False
    _write(path, updated)
    return True


def _update_toml_version(path: Path, coordinate: str, version: str) -> bool:
    """Replace only a supported catalog entry or its version reference."""
    hit = _toml_library_version(path, coordinate) or _toml_plugin_version(
        path, coordinate
    )
    if hit is None:
        return False
    _current, ref = hit
    text = _read(path)
    if ref == "inline":
        group, artifact = _split_maven_name(coordinate)
        patterns = [
            re.compile(
                rf'(module\s*=\s*"{re.escape(coordinate)}"\s*,\s*version\s*=\s*")[^"]+(")'
            )
        ]
        if group and artifact:
            patterns.append(
                re.compile(
                    rf'(group\s*=\s*"{re.escape(group)}"\s*,\s*'
                    rf'name\s*=\s*"{re.escape(artifact)}"\s*,\s*version\s*=\s*")[^"]+(")'
                )
            )
        patterns.append(
            re.compile(
                rf'(id\s*=\s*"{re.escape(coordinate)}"\s*,\s*version\s*=\s*")[^"]+(")'
            )
        )
    else:
        patterns = [re.compile(rf'(?m)^({re.escape(ref)}\s*=\s*")[^"]+(")')]
    updated, count = text, 0
    for pattern in patterns:
        updated, count = pattern.subn(
            lambda match: _replace_groups(match, version), text, count=1
        )
        if count == 1:
            break
    if count != 1:
        return False
    _write(path, updated)
    return True


def _gradle_map_pattern(package: str) -> re.Pattern[str] | None:
    """Match one Gradle map declaration for a ``group:artifact`` coordinate.

    Group 1 is the text through the version quote. Group 5 is the version.
    """
    group, artifact = _split_maven_name(package)
    if not group or not artifact:
        return None
    return re.compile(
        rf"""(group\s*[:=]\s*(['\"]){re.escape(group)}\2\s*,\s*"""
        rf"""name\s*[:=]\s*(['\"]){re.escape(artifact)}\3\s*,\s*"""
        rf"""version\s*[:=]\s*(['\"]))([^'\"]+)"""
    )


def _gradle_map_version(text: str, package: str) -> str | None:
    """Return the version from a Gradle map declaration, when one exists."""
    pattern = _gradle_map_pattern(package)
    if pattern is None:
        return None
    match = pattern.search(text)
    return match.group(5) if match else None


def _plugin_pattern(plugin_id: str) -> re.Pattern[str]:
    """Match one Gradle ``plugins`` id and the quote that opens its version."""
    return re.compile(
        rf"""(id\s*(?:\(\s*)?(['\"]){re.escape(plugin_id)}\2(?:\s*\))?\s+"""
        rf"""version\s+(['\"]))([^'\"]+)"""
    )


def _plugin_version(text: str, plugin_id: str) -> str | None:
    """Return the version from a Gradle plugins declaration, when one exists."""
    match = _plugin_pattern(plugin_id).search(text)
    return match.group(4) if match else None


def _replace_plugin(text: str, plugin_id: str, version: str) -> tuple[str, int]:
    """Replace one Gradle plugin version and leave every other plugin alone."""
    return _plugin_pattern(plugin_id).subn(
        lambda match: f"{match.group(1)}{version}", text, count=1
    )


def _toml_plugin_version(path: Path, plugin_id: str) -> tuple[str, str] | None:
    """Return a catalog plugin version and ``inline`` or its version ref."""
    try:
        data = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError:
        return None
    for library in (data.get("plugins") or {}).values():
        if not isinstance(library, dict) or library.get("id") != plugin_id:
            continue
        declared = library.get("version")
        if isinstance(declared, str):
            return declared, "inline"
        ref = declared.get("ref") if isinstance(declared, dict) else None
        versions = data.get("versions") or {}
        if isinstance(ref, str) and isinstance(versions.get(ref), str):
            return versions[ref], ref
    return None


def _replace_gradle_map(text: str, package: str, version: str) -> tuple[str, int]:
    """Replace one Gradle ``group``/``name``/``version`` declaration."""
    pattern = _gradle_map_pattern(package)
    if pattern is None:
        return text, 0
    return pattern.subn(lambda match: f"{match.group(1)}{version}", text, count=1)


def _is_dockerfile(path: Path) -> bool:
    """Recognize Dockerfile names without treating arbitrary files as images."""
    name = path.name.lower()
    return name == "dockerfile" or name.endswith(".dockerfile")


def update_dockerfile_tag(
    root: Path, image: str, new_tag: str, files: list[Path] | None = None
) -> list[str]:
    """Move every unpinned ``FROM name:current`` line to ``new_tag``.

    Every Dockerfile and every stage is updated, so a multi-stage build is
    not left half on the vulnerable tag. Digest pins are left alone.
    Return the repo-relative paths that changed.
    """
    name, current = _image_name_tag(image)
    if not name or not current:
        return []
    if files is None:
        files, _truncated = iter_files(root)
    pattern = re.compile(
        rf"^(FROM[ \t]+){re.escape(name)}:{re.escape(current)}(?![@\w.-])([ \t]+AS[ \t]+\S+)?(?=[ \t]*\r?$)",
        re.IGNORECASE | re.MULTILINE,
    )
    changed: list[str] = []
    for path in (item for item in files if _is_dockerfile(item)):
        text = _read(path)
        updated, count = pattern.subn(
            lambda match: f"{match.group(1)}{name}:{new_tag}{match.group(2) or ''}",
            text,
        )
        if count:
            _write(path, updated)
            changed.append(_rel(root, path))
    return changed


def _image_name_tag(image: str) -> tuple[str | None, str | None]:
    """Split an image tag and reject digest-pinned or untagged references."""
    if "@" in image:
        return None, None
    if ":" not in image:
        return image, None
    name, tag = image.rsplit(":", 1)
    return name, tag


def spec_already_allows(hit: PackageHit, fixed: str) -> bool:
    """Return whether the declared npm range already accepts the fixed version."""
    if hit.ecosystem != "npm" or not hit.spec:
        return False
    return range_allows(hit.spec, fixed)


def bumped_spec(hit: PackageHit, fixed: str) -> str | None:
    """Return the npm spec raised to ``fixed``, keeping ^ or ~."""
    if hit.ecosystem != "npm" or not hit.spec:
        return None
    return bump_npm_spec(hit.spec, fixed)


def dockerfile_images(root: Path, files: list[Path] | None = None) -> list[str]:
    """Return every base image named on a FROM line."""
    if files is None:
        files, _truncated = iter_files(root)
    images: list[str] = []
    pattern = re.compile(
        r"^FROM[ \t]+(?:--\S+[ \t]+)*(\S+)", re.IGNORECASE | re.MULTILINE
    )
    for path in (item for item in files if _is_dockerfile(item)):
        images.extend(
            pattern.findall(path.read_text(encoding="utf-8", errors="replace"))
        )
    return images
