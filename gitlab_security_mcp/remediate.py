"""Choose and apply the smallest supportable fix. Score 1 is the smallest."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gitlab_security_mcp.commands import CommandRunner, resolve_tool
from gitlab_security_mcp.manifests import (
    DEPENDENCY_SECTIONS,
    PackageHit,
    add_java_override,
    add_npm_override,
    add_nuget_reference,
    bumped_spec,
    dockerfile_images,
    gradle_uses_enforced_platform,
    gradle_version_files,
    image_name_tag,
    is_modern_yarn,
    spec_already_allows,
    update_csproj_version,
    update_dockerfile_tag,
    update_gradle_version,
    update_npm_spec,
    update_pom_version,
)
from gitlab_security_mcp.official_docs import manager_documentation
from gitlab_security_mcp.util import json_object, log_unexpected, resolve_inside
from gitlab_security_mcp.versions import parse_version

_RAISE_REFUSING_TO_READ_OUTSIDE_THE_REPOSITORY = (
    "Refusing to read outside the repository: {}"
)
_RAISE_REFUSING_A_LOCKFILE_REFRESH_OUTSIDE_THE_REPOSITORY = (
    "Refusing a lockfile refresh outside the repository: {}"
)

MAX_AUTO_SCORE = 3
PACKAGE_TIMEOUT = 300
# Versions come from public advisories and are written into manifests and
# regex replacements, so only plain version characters are accepted.
_SAFE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_SAFE_PACKAGE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,213}$")


def safe_version(value: str | None) -> bool:
    """Return whether a version string is safe to write into a manifest."""
    return (
        bool(value)
        and bool(_SAFE_VERSION.fullmatch(value))
        and parse_version(value) is not None
    )


@dataclass
class Plan:
    """One minimal edit. ``score`` 1 is a lockfile refresh, 3 is an override or image tag."""

    strategy: str
    score: int
    ecosystem: str
    package: str
    installed: str | None
    target: str
    files: list[str]
    manager: str | None
    description: str
    oracle: str | None = None
    line: int | None = None
    expected_line: str | None = None
    replacement_line: str | None = None
    line_edits: tuple[dict, ...] = ()
    doc_pages: tuple[dict, ...] = ()
    gradle_configurations: tuple[str, ...] = ()
    gradle_force: bool = False

    def as_dict(self) -> dict:
        """Return the plan as plain JSON-safe data."""
        return {
            "strategy": self.strategy,
            "score": self.score,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "installed": self.installed,
            "target": self.target,
            "files": self.files,
            "manager": self.manager,
            "description": self.description,
            "oracle": self.oracle,
            "line": self.line,
            "expected_line": self.expected_line,
            "replacement_line": self.replacement_line,
            "line_edits": [dict(edit) for edit in self.line_edits],
            "doc_pages": [
                {
                    "name": page["name"],
                    "url": page["url"],
                    "markers": list(page["markers"]),
                }
                for page in self.doc_pages
            ],
            "gradle_configurations": list(self.gradle_configurations),
            "gradle_force": self.gradle_force,
            "qualifiers": {
                "status": "REQUIRED",
                "package": self.package,
                "target": self.target,
                "requirements": [
                    "Select the latest supported stable release compatible with the actual project runtime, including major upgrades; the advisory fix is only a minimum.",
                    "Review complete official package documentation and API changes.",
                    "Do not adapt production/unit-test APIs or check scripts; reject known incompatibilities.",
                    "Block paid/restricted target versions and flag them for user investigation. Warn explicitly about unverified licensing; obey stricter configured corporate policy when present.",
                    "Require production builds, exact resolved-dependency proof and test-free configured policy checks. Never run unit/integration tests. Revert offending updates while retaining passing updates.",
                ],
                "manager_documentation": manager_documentation(
                    {"manager": self.manager}
                ),
            }
            if self.ecosystem in {"npm", "NuGet", "Maven"}
            else None,
        }


def plan_remediation(
    root: Path,
    finding: dict,
    hit: PackageHit | None,
    fixed: str | None,
    files: list[Path] | None = None,
) -> tuple[Plan | None, str]:
    """Pick the lowest-scoring edit that moves the finding to ``fixed``.

    Return the plan and its description, or None and the reason no plan fits.
    """
    if not fixed:
        return None, "No fixed version is available to plan against."
    if not safe_version(fixed):
        return None, f"The advisory version {fixed!r} is not a plain version string."
    if hit is not None and not _SAFE_PACKAGE.fullmatch(hit.name):
        return (
            None,
            f"The package name {hit.name!r} is not safe to write into a manifest.",
        )
    installed = (hit.version if hit else None) or finding.get("installedVersion")
    installed_version = parse_version(installed)
    if installed_version is not None and installed_version >= parse_version(fixed):
        return None, f"Installed version {installed} is already at or above {fixed}."

    image_plan = _image_plan(root, finding, fixed, files)
    package_plan = _package_plan(hit, fixed) if hit else None
    if (
        package_plan
        and package_plan.manager == "gradle"
        and ":" in package_plan.package
    ):
        configuration = (finding.get("location") or {}).get(
            "configuration"
        ) or "runtimeClasspath"
        scopes = tuple(sorted(hit.configuration_versions or {}))
        names = {scope.rsplit(":", 1)[-1] for scope in scopes}
        if scopes and (
            configuration not in names
            or names - {"runtimeClasspath", "compileClasspath"}
        ):
            if any(
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,100}", name) is None
                for name in names
            ):
                return (
                    None,
                    "Gradle reported an unsupported configuration name; no override scope was guessed.",
                )
            package_plan.strategy = "override"
            package_plan.score = 3
            package_plan.gradle_configurations = scopes
            manifest = (finding.get("dependencyResolution") or {}).get(
                "manifest"
            ) or hit.manifest
            if Path(manifest).name not in {"build.gradle", "build.gradle.kts"}:
                return (
                    None,
                    "A scoped Gradle resolution override requires the owning build file.",
                )
            package_plan.files = [manifest]
            package_plan.description = (
                f"Add a scoped Gradle resolutionStrategy.force security override for "
                f"{hit.name} from {installed} to {fixed} in {manifest}; "
                f"configurations: {', '.join(scopes)}. Preserve the existing dependency graph "
                "and require the exact target in every observed configuration after a production build; no tests."
            )
        elif package_plan.strategy == "override" and configuration not in {
            "runtimeClasspath",
            "compileClasspath",
        }:
            return (
                None,
                "A custom Gradle override requires observed configuration evidence.",
            )
        try:
            manifest = (finding.get("dependencyResolution") or {}).get(
                "manifest"
            ) or hit.manifest
            if (
                package_plan.strategy == "override"
                and not package_plan.gradle_configurations
                and manifest
                and gradle_uses_enforced_platform(root, manifest)
            ):
                package_plan.gradle_force = True
                package_plan.gradle_configurations = scopes
                package_plan.files = [manifest]
                package_plan.description = (
                    f"Force only {hit.name} from {installed} to {fixed} across configurations "
                    f"in {manifest}, which declares enforcedPlatform. Preserve the BOM and "
                    "other coordinates; require exact resolved-version proof and a production "
                    "build. Runtime compatibility with the platform remains unverified; no tests."
                )
            package_plan.files = gradle_version_files(
                root,
                package_plan.files[0],
                hit.name,
                override=package_plan.strategy == "override",
            )
        except (OSError, ValueError) as exc:
            return None, str(exc)
    candidates = [item for item in (package_plan, image_plan) if item is not None]
    if not candidates:
        if hit is None:
            return (
                None,
                "No manifest, lockfile, or image tag can be updated for this finding.",
            )
        return None, "The package was found, but the manifest cannot be bumped safely."
    candidates.sort(key=lambda item: item.score)
    best = candidates[0]
    if best.score > MAX_AUTO_SCORE:
        return (
            None,
            f"The smallest candidate edit scores {best.score}, above the auto-fix limit of {MAX_AUTO_SCORE}.",
        )
    return best, best.description


def _package_plan(hit: PackageHit, fixed: str) -> Plan | None:
    """Choose a supported dependency edit, preferring minimal changes."""
    if hit.ecosystem == "npm":
        if hit.direct and hit.spec and spec_already_allows(hit, fixed) and hit.lockfile:
            return Plan(
                strategy="lockfile_only",
                score=1,
                ecosystem=hit.ecosystem,
                package=hit.name,
                installed=hit.version,
                target=fixed,
                files=[hit.lockfile],
                manager=hit.manager,
                description=f"Refresh the {hit.manager} lockfile for {hit.name}; {hit.spec} already allows {fixed}.",
            )
        if hit.direct and hit.manifest and hit.spec:
            new_spec = bumped_spec(hit, fixed)
            if new_spec:
                files = [hit.manifest]
                if hit.lockfile:
                    files.append(hit.lockfile)
                return Plan(
                    strategy="manifest_bump",
                    score=2,
                    ecosystem=hit.ecosystem,
                    package=hit.name,
                    installed=hit.version,
                    target=fixed,
                    files=files,
                    manager=hit.manager,
                    description=f"Raise {hit.name} in {hit.manifest} from {hit.spec} to {new_spec}.",
                )
        if hit.manager in {"npm", "pnpm", "yarn"}:
            return Plan(
                strategy="override",
                score=3,
                ecosystem=hit.ecosystem,
                package=hit.name,
                installed=hit.version,
                target=fixed,
                files=[
                    hit.override_manifest or hit.manifest or "package.json",
                    hit.lockfile,
                ]
                if hit.lockfile
                else [hit.override_manifest or hit.manifest or "package.json"],
                manager=hit.manager,
                description=f"Pin transitive dependency {hit.name} to {fixed} with a {hit.manager} override.",
            )
        return None
    if hit.manager in {"maven", "gradle"} and hit.manifest and not hit.direct:
        return Plan(
            strategy="override",
            score=3,
            ecosystem=hit.ecosystem,
            package=hit.name,
            installed=hit.version,
            target=fixed,
            files=[hit.manifest],
            manager=hit.manager,
            description=f"Constrain observed transitive {hit.name} to {fixed} in {hit.manifest}; require configuration-specific resolution and a production build, without tests.",
        )
    if hit.manager == "maven" and hit.manifest and hit.direct:
        return Plan(
            strategy="manifest_bump",
            score=2,
            ecosystem=hit.ecosystem,
            package=hit.name,
            installed=hit.version,
            target=fixed,
            files=[hit.manifest],
            manager="maven",
            description=f"Set {hit.name} in {hit.manifest} to {fixed}.",
        )
    if hit.manager == "gradle" and hit.manifest and hit.direct:
        return Plan(
            strategy="manifest_bump",
            score=2,
            ecosystem=hit.ecosystem,
            package=hit.name,
            installed=hit.version,
            target=fixed,
            files=[hit.manifest],
            manager="gradle",
            description=f"Set {hit.name} in {hit.manifest} to {fixed}.",
        )
    if hit.manager == "nuget":
        files = [hit.manifest] if hit.manifest else []
        if hit.lockfile:
            files.append(hit.lockfile)
        if hit.direct and hit.manifest:
            return Plan(
                strategy="manifest_bump",
                score=2,
                ecosystem=hit.ecosystem,
                package=hit.name,
                installed=hit.version,
                target=fixed,
                files=files,
                manager="nuget",
                description=f"Set {hit.name} in {hit.manifest} to {fixed}.",
            )
        return Plan(
            strategy="override",
            score=3,
            ecosystem=hit.ecosystem,
            package=hit.name,
            installed=hit.version,
            target=fixed,
            files=files or ["*.csproj"],
            manager="nuget",
            description=f"Add a direct PackageReference so transitive {hit.name} resolves to {fixed}.",
        )
    return None


def _image_plan(
    root: Path, finding: dict, fixed: str, files: list[Path] | None
) -> Plan | None:
    """Plan a matching unpinned image-tag update, never a digest rewrite."""
    image = (finding.get("location") or {}).get("image")
    component = finding.get("component") or ""
    if image:
        name, _tag = image_name_tag(image)
    else:
        name = None
    if name and component and not _same_image(component, name, image):
        return None
    if not name:
        for candidate in dockerfile_images(root, files):
            candidate_name, _tag = image_name_tag(candidate)
            if candidate_name and _same_image(component, candidate_name, candidate):
                name = candidate_name
                image = candidate
                break
    if not name or "@" in (image or ""):
        return None
    oracle = f"{name}:{fixed}"
    return Plan(
        strategy="image_tag",
        score=3,
        ecosystem="container",
        package=name,
        installed=(image or "").split(":", 1)[-1] if image and ":" in image else None,
        target=fixed,
        files=["Dockerfile"],
        manager=None,
        description=f"Move the {name} base image tag to {fixed}.",
        oracle=oracle,
    )


def _same_image(component: str, name: str, image: str | None) -> bool:
    """Match a scanner component to an image name or repository basename."""
    if not component:
        return True
    repo = name.rsplit("/", 1)[-1]
    return component in {name, repo, image}


def apply_plan(
    root: Path,
    plan: Plan,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> dict:
    """Apply one supported local plan and refresh relevant lockfiles.

    root bounds edited paths; runner and which control allowed tools.
    Return APPLIED or a structured failure with edited files and commands.
    A failed refresh can leave a manifest change for manual review; this
    function does not roll back, stage, commit, or publish changes.
    """
    edited: list[str] = []
    commands: list[str] = []
    if plan.strategy != "config_line" and not safe_version(plan.target):
        return _failed(
            "FIX_FAILED", plan, f"Refusing unsafe target version {plan.target!r}."
        )
    if plan.manager in {"maven", "gradle"} and not plan.files:
        return _failed(
            "FIX_FAILED", plan, "The plan does not name a build file to edit."
        )
    try:
        if plan.strategy == "config_line":
            from gitlab_security_mcp.config_findings import apply_config_line

            return _applied(plan, apply_config_line(root, plan), commands)
        if plan.strategy == "image_tag":
            token = (
                f"{plan.package}:{plan.installed}" if plan.installed else plan.package
            )
            paths = update_dockerfile_tag(root, token, plan.target)
            if not paths:
                return _failed(
                    "FIX_FAILED", plan, "No matching unpinned FROM line was updated."
                )
            return _applied(plan, paths, commands)
        if plan.manager in {"npm", "pnpm", "yarn"}:
            return _apply_node(root, plan, runner, which, edited, commands)
        if plan.manager == "maven":
            manifest = plan.files[0]
            if plan.strategy == "override":
                add_java_override(root, manifest, plan.package, plan.target)
                return _applied(plan, [manifest], commands)
            if not update_pom_version(root, manifest, plan.package, plan.target):
                return _failed("FIX_FAILED", plan, f"Could not update {manifest}.")
            return _applied(plan, [manifest], commands)
        if plan.manager == "gradle":
            manifest = plan.files[0]
            if plan.strategy == "override":
                add_java_override(
                    root,
                    manifest,
                    plan.package,
                    plan.target,
                    configurations=plan.gradle_configurations,
                    force=plan.gradle_force,
                )
                return _applied(plan, plan.files, commands)
            if not update_gradle_version(root, manifest, plan.package, plan.target):
                return _failed("FIX_FAILED", plan, f"Could not update {manifest}.")
            return _applied(plan, plan.files, commands)
        if plan.manager == "nuget":
            return _apply_nuget(root, plan, runner, which, edited, commands)
    except (OSError, ValueError, RuntimeError, TypeError, AttributeError) as exc:
        log_unexpected(exc, f"applying {plan.strategy} plan for {plan.package}")
        return _failed("FIX_FAILED", plan, str(exc), edited, commands)
    return _failed("FIX_FAILED", plan, "No applicator matched this plan.")


def _apply_node(root, plan, runner, which, edited, commands) -> dict:
    """Apply a Node edit and record any failed lockfile refresh separately."""
    if plan.strategy == "manifest_bump":
        manifest = next(
            (path for path in plan.files if path.endswith("package.json")), None
        )
        if manifest is None:
            return _failed(
                "FIX_FAILED", plan, "The plan does not name a package.json to edit."
            )
        new_spec = _node_spec(root, manifest, plan)
        if new_spec is None:
            return _failed(
                "FIX_FAILED", plan, "Could not derive a replacement npm spec."
            )
        if not update_npm_spec(root, manifest, plan.package, new_spec):
            return _failed(
                "FIX_FAILED", plan, f"Could not update {plan.package} in {manifest}."
            )
        edited.append(manifest)
        if any(
            path.endswith(("lock.json", "lock.yaml")) or Path(path).name == "yarn.lock"
            for path in plan.files
        ):
            return _refresh_node_lock(
                root,
                plan,
                runner,
                which,
                edited,
                commands,
                fallback_status="FIX_FAILED_LOCKFILE",
            )
        return _applied(plan, edited, commands)
    if plan.strategy == "override":
        manifest = next(
            (
                path
                for path in plan.files
                if Path(path).name in {"package.json", "pnpm-workspace.yaml"}
            ),
            "package.json",
        )
        edited.append(
            add_npm_override(
                root, plan.package, plan.target, plan.manager or "npm", manifest
            )
        )
        return _refresh_node_lock(
            root,
            plan,
            runner,
            which,
            edited,
            commands,
            fallback_status="FIX_FAILED_LOCKFILE",
        )
    if plan.strategy == "lockfile_only":
        return _refresh_node_lock(
            root,
            plan,
            runner,
            which,
            edited,
            commands,
            fallback_status="FIX_FAILED_LOCKFILE",
        )
    return _failed("FIX_FAILED", plan, "Unsupported node strategy.")


def _node_spec(root: Path, manifest: str, plan: Plan) -> str | None:
    """Derive a replacement spec from the current local dependency entry."""
    path = resolve_inside(root, manifest)
    if path is None:
        raise ValueError(
            _RAISE_REFUSING_TO_READ_OUTSIDE_THE_REPOSITORY.format(manifest)
        )
    data = json_object(path.read_text(encoding="utf-8"))
    for section in DEPENDENCY_SECTIONS:
        specs = data.get(section) or {}
        if isinstance(specs, dict) and isinstance(specs.get(plan.package), str):
            hit = PackageHit(
                ecosystem="npm",
                manager=plan.manager or "npm",
                name=plan.package,
                version=plan.installed,
                spec=specs[plan.package],
                manifest=manifest,
                lockfile=None,
                direct=True,
            )
            return bumped_spec(hit, plan.target)
    return None


def _refresh_node_lock(
    root, plan, runner, which, edited, commands, *, fallback_status: str
) -> dict:
    """Refresh dependencies with manager-specific remediation commands."""
    entry = next(
        (
            path
            for path in plan.files
            if Path(path).name in {"pnpm-lock.yaml", "yarn.lock", "package-lock.json"}
        ),
        plan.files[0] if plan.files else "package.json",
    )
    resolved = resolve_inside(root, entry)
    if resolved is None:
        raise ValueError(
            _RAISE_REFUSING_A_LOCKFILE_REFRESH_OUTSIDE_THE_REPOSITORY.format(entry)
        )
    workdir = resolved.parent
    tool = resolve_tool(plan.manager or "npm", which)
    if not tool:
        return _failed(
            fallback_status,
            plan,
            f"{plan.manager} is not on PATH, so the lockfile was not refreshed.",
            edited,
        )
    if plan.manager == "yarn" and is_modern_yarn(workdir):
        if plan.strategy == "lockfile_only":
            return _failed(
                fallback_status,
                plan,
                "Recursive Yarn refresh cannot guarantee script-free execution. Use a reviewed explicit version/resolution update instead; no tests or hooks were run.",
                edited,
                commands,
            )
        else:
            argv = [tool, "install", "--mode=update-lockfile"]
    elif plan.strategy == "lockfile_only" and plan.manager == "npm":
        argv = [
            tool,
            "update",
            plan.package,
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    elif plan.strategy == "lockfile_only" and plan.manager == "pnpm":
        argv = [tool, "update", plan.package, "--ignore-scripts"]
    elif plan.strategy == "lockfile_only" and plan.manager == "yarn":
        argv = [tool, "upgrade", plan.package, "--ignore-scripts"]
    elif plan.manager == "npm":
        argv = [
            tool,
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    elif plan.manager == "pnpm":
        argv = [tool, "install", "--lockfile-only", "--ignore-scripts"]
    else:
        argv = [tool, "upgrade", f"{plan.package}@{plan.target}", "--ignore-scripts"]
    options = {"cwd": workdir} if workdir != root.resolve() else {}
    result = runner.run(argv, timeout=PACKAGE_TIMEOUT, check=False, **options)
    commands.append(result.display())
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout).strip()[:500]
        return _failed(
            fallback_status,
            plan,
            f"Lockfile refresh failed: {detail}",
            edited,
            commands,
        )
    for path in plan.files:
        if path not in edited:
            edited.append(path)
    return _applied(plan, edited, commands)


def _apply_nuget(root, plan, runner, which, edited, commands) -> dict:
    """Edit NuGet references and restore an existing dependency lockfile."""
    if plan.strategy == "manifest_bump" and plan.files:
        manifest = plan.files[0]
        if not update_csproj_version(root, manifest, plan.package, plan.target):
            return _failed(
                "FIX_FAILED", plan, f"Could not update {plan.package} in {manifest}."
            )
        edited.append(manifest)
    else:
        manifest = add_nuget_reference(root, plan.package, plan.target)
        if not manifest:
            return _failed(
                "FIX_FAILED",
                plan,
                "Could not add a PackageReference. More than one project, or no ItemGroup.",
            )
        edited.append(manifest)
    if any(path.endswith("packages.lock.json") for path in plan.files):
        lock = next(path for path in plan.files if path.endswith("packages.lock.json"))
        resolved = resolve_inside(root, lock)
        if resolved is None:
            raise ValueError(
                _RAISE_REFUSING_A_LOCKFILE_REFRESH_OUTSIDE_THE_REPOSITORY.format(lock)
            )
        tool = resolve_tool("dotnet", which)
        if not tool:
            return _failed(
                "FIX_FAILED_LOCKFILE",
                plan,
                "dotnet is not on PATH, so packages.lock.json was not refreshed.",
                edited,
            )
        result = runner.run(
            [tool, "restore"],
            timeout=PACKAGE_TIMEOUT,
            check=False,
            cwd=resolved.parent,
        )
        commands.append(result.display())
        if result.exit_code != 0:
            return _failed(
                "FIX_FAILED_LOCKFILE",
                plan,
                (result.stderr or result.stdout)[:500],
                edited,
                commands,
            )
        edited.append(lock)
    return _applied(plan, edited, commands)


def _applied(plan: Plan, files: list[str], commands: list[str]) -> dict:
    """Return successful edit metadata with duplicate paths removed."""
    unique = []
    for path in files:
        if path and path not in unique:
            unique.append(path)
    return {
        "status": "APPLIED",
        "files": unique,
        "commands": commands,
        "description": plan.description,
        "strategy": plan.strategy,
        "oracle": plan.oracle,
        "target": plan.target,
    }


def _failed(
    status: str,
    plan: Plan,
    detail: str,
    files: list[str] | None = None,
    commands: list[str] | None = None,
) -> dict:
    """Preserve partial edit evidence alongside the failed plan's details."""
    return {
        "status": status,
        "files": files or [],
        "commands": commands or [],
        "description": plan.description,
        "strategy": plan.strategy,
        "oracle": plan.oracle,
        "target": plan.target,
        "detail": detail,
    }
