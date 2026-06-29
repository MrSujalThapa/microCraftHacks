"""Normalize TypeScript scan and routed skill artifacts into typed runtime state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyber_swarm.models.errors import RuntimeInputError
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    StackDetection,
    SurfaceAuth,
    SurfaceDataModel,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.schemas.io import load_json


def _require_string(data: dict[str, Any], field: str, errors: list[str]) -> str | None:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} must be a non-empty string")
        return None
    return value


def _parse_inventory(data: dict[str, Any], errors: list[str]) -> InventoryResult | None:
    inventory = data.get("inventory")
    if not isinstance(inventory, dict):
        errors.append("inventory must be an object")
        return None

    total_files = inventory.get("totalFiles")
    if not isinstance(total_files, int) or total_files < 0:
        errors.append("inventory.totalFiles must be a non-negative integer")
        return None

    by_category = inventory.get("byCategory")
    if not isinstance(by_category, dict):
        errors.append("inventory.byCategory must be an object")
        return None

    files_raw = inventory.get("files")
    if not isinstance(files_raw, list):
        errors.append("inventory.files must be an array")
        return None

    files: list[FileInventoryItem] = []
    for index, item in enumerate(files_raw):
        if not isinstance(item, dict):
            errors.append(f"inventory.files[{index}] must be an object")
            continue
        path = item.get("path")
        category = item.get("category")
        if not isinstance(path, str) or not path:
            errors.append(f"inventory.files[{index}].path must be a non-empty string")
            continue
        if not isinstance(category, str) or not category:
            errors.append(f"inventory.files[{index}].category must be a non-empty string")
            continue
        files.append(FileInventoryItem(path=path, category=category))

    normalized_categories = {
        str(key): int(value)
        for key, value in by_category.items()
        if isinstance(key, str) and isinstance(value, int)
    }

    return InventoryResult(
        total_files=total_files,
        by_category=normalized_categories,
        files=files,
    )


def _parse_stack(data: dict[str, Any]) -> list[StackDetection]:
    stack_raw = data.get("stack", [])
    if stack_raw is None:
        return []
    if not isinstance(stack_raw, list):
        raise RuntimeInputError("stack must be an array when present")

    stack: list[StackDetection] = []
    for index, item in enumerate(stack_raw):
        if not isinstance(item, dict):
            raise RuntimeInputError(f"stack[{index}] must be an object")
        name = item.get("name")
        confidence = item.get("confidence")
        evidence = item.get("evidence")
        if not isinstance(name, str) or not name:
            raise RuntimeInputError(f"stack[{index}].name must be a non-empty string")
        if not isinstance(confidence, str) or not confidence:
            raise RuntimeInputError(f"stack[{index}].confidence must be a non-empty string")
        if not isinstance(evidence, list) or not all(isinstance(entry, str) for entry in evidence):
            raise RuntimeInputError(f"stack[{index}].evidence must be a string array")
        stack.append(
            StackDetection(name=name, confidence=confidence, evidence=list(evidence))
        )
    return stack


def _parse_surfaces(data: dict[str, Any]) -> SurfacesResult:
    surfaces_raw = data.get("surfaces")
    if surfaces_raw is None:
        return SurfacesResult()
    if not isinstance(surfaces_raw, dict):
        raise RuntimeInputError("surfaces must be an object when present")

    def parse_routes(key: str) -> list[SurfaceRoute]:
        routes_raw = surfaces_raw.get(key, [])
        if routes_raw is None:
            return []
        if not isinstance(routes_raw, list):
            raise RuntimeInputError(f"surfaces.{key} must be an array")
        routes: list[SurfaceRoute] = []
        for index, item in enumerate(routes_raw):
            if not isinstance(item, dict):
                raise RuntimeInputError(f"surfaces.{key}[{index}] must be an object")
            path = item.get("path")
            file = item.get("file")
            if not isinstance(path, str) or not path:
                raise RuntimeInputError(f"surfaces.{key}[{index}].path must be a non-empty string")
            if not isinstance(file, str) or not file:
                raise RuntimeInputError(f"surfaces.{key}[{index}].file must be a non-empty string")
            framework = item.get("framework")
            routes.append(
                SurfaceRoute(
                    path=path,
                    file=file,
                    framework=framework if isinstance(framework, str) else None,
                )
            )
        return routes

    auth_raw = surfaces_raw.get("auth", [])
    if auth_raw is None:
        auth_raw = []
    if not isinstance(auth_raw, list):
        raise RuntimeInputError("surfaces.auth must be an array")
    auth: list[SurfaceAuth] = []
    for index, item in enumerate(auth_raw):
        if not isinstance(item, dict):
            raise RuntimeInputError(f"surfaces.auth[{index}] must be an object")
        file = item.get("file")
        if not isinstance(file, str) or not file:
            raise RuntimeInputError(f"surfaces.auth[{index}].file must be a non-empty string")
        auth_type = item.get("type")
        auth.append(
            SurfaceAuth(
                file=file,
                type=auth_type if isinstance(auth_type, str) else None,
            )
        )

    models_raw = surfaces_raw.get("dataModels", [])
    if models_raw is None:
        models_raw = []
    if not isinstance(models_raw, list):
        raise RuntimeInputError("surfaces.dataModels must be an array")
    data_models: list[SurfaceDataModel] = []
    for index, item in enumerate(models_raw):
        if not isinstance(item, dict):
            raise RuntimeInputError(f"surfaces.dataModels[{index}] must be an object")
        file = item.get("file")
        if not isinstance(file, str) or not file:
            raise RuntimeInputError(f"surfaces.dataModels[{index}].file must be a non-empty string")
        name = item.get("name")
        data_models.append(
            SurfaceDataModel(
                file=file,
                name=name if isinstance(name, str) else None,
            )
        )

    return SurfacesResult(
        routes=parse_routes("routes"),
        api=parse_routes("api"),
        auth=auth,
        data_models=data_models,
    )


def normalize_scan_report(data: dict[str, Any]) -> RepoIntelligence:
    errors: list[str] = []
    version = _require_string(data, "version", errors) or "0.0.0"
    scanned_at = _require_string(data, "scannedAt", errors)
    project_root = _require_string(data, "projectRoot", errors)
    inventory = _parse_inventory(data, errors)

    if errors:
        raise RuntimeInputError("; ".join(errors))
    assert scanned_at is not None
    assert project_root is not None
    assert inventory is not None

    return RepoIntelligence(
        version=version,
        scanned_at=scanned_at,
        project_root=project_root,
        inventory=inventory,
        stack=_parse_stack(data),
        surfaces=_parse_surfaces(data),
    )


def normalize_routed_skills(data: dict[str, Any]) -> RoutedSkills:
    errors: list[str] = []
    report_path = _require_string(data, "reportPath", errors)
    routed_at = _require_string(data, "routedAt", errors)

    selected_raw = data.get("selected")
    if not isinstance(selected_raw, list):
        errors.append("selected must be an array")

    selected: list[SelectedSkill] = []
    if isinstance(selected_raw, list):
        for index, item in enumerate(selected_raw):
            if not isinstance(item, dict):
                errors.append(f"selected[{index}] must be an object")
                continue
            name = item.get("name")
            path = item.get("path")
            score = item.get("score")
            reasons = item.get("reasons")
            agent_types = item.get("agentTypes")
            if not isinstance(name, str) or not name:
                errors.append(f"selected[{index}].name must be a non-empty string")
                continue
            if not isinstance(path, str) or not path:
                errors.append(f"selected[{index}].path must be a non-empty string")
                continue
            if not isinstance(score, (int, float)):
                errors.append(f"selected[{index}].score must be a number")
                continue
            if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
                errors.append(f"selected[{index}].reasons must be a string array")
                continue
            if not isinstance(agent_types, list) or not all(
                isinstance(agent_type, str) for agent_type in agent_types
            ):
                errors.append(f"selected[{index}].agentTypes must be a string array")
                continue
            selected.append(
                SelectedSkill(
                    name=name,
                    path=path,
                    score=float(score),
                    reasons=list(reasons),
                    agent_types=list(agent_types),
                )
            )

    if errors:
        raise RuntimeInputError("; ".join(errors))
    assert report_path is not None
    assert routed_at is not None

    return RoutedSkills(
        report_path=report_path,
        routed_at=routed_at,
        selected=selected,
    )


def normalize_runtime_input(scan_report_path: Path, routed_skills_path: Path) -> RuntimeInput:
    scan_report = load_json(scan_report_path)
    routed_skills = load_json(routed_skills_path)

    return RuntimeInput(
        scan_report_path=scan_report_path,
        routed_skills_path=routed_skills_path,
        repo=normalize_scan_report(scan_report),
        routed_skills=normalize_routed_skills(routed_skills),
    )
