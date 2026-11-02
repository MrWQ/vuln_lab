from __future__ import annotations

import hashlib
import html
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from vuln_kb.config import settings
from vuln_kb.models import KnowledgeEntry, MaterialVariant, Product, ProductVulnerability
from vuln_kb.storage import ObjectStore


def _slug(value: str | None) -> str:
    slug = re.sub(r"[^\w.-]+", "_", value or "未知", flags=re.UNICODE).strip("._")[:90] or "未知"
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    return f"_{slug}" if slug.upper() in reserved else slug


def _md(value: str | None) -> str:
    value = html.escape(" ".join((value or "").split()), quote=False)
    for char in ("\\", chr(96), "[", "]", "(", ")", "#", "*", "_", "!"):
        value = value.replace(char, "\\" + char)
    return value


def _md_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return quote(value, safe=":/?&=%#@+;,~!*-$._")


def _rel(from_dir: Path, to_file: Path) -> str:
    return Path(os.path.relpath(to_file, from_dir)).as_posix()


def _product_category(openness: str) -> str:
    return {"open_source": "开源", "closed_source": "不开源"}.get(openness, "待确认")


def publish_export(db: Session) -> Path:
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    generation = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    staging = settings.export_dir / f".staging-{generation}"
    staging.mkdir(parents=True, exist_ok=False)
    query = (select(KnowledgeEntry).where(KnowledgeEntry.status == "published")
             .options(joinedload(KnowledgeEntry.products).joinedload(ProductVulnerability.product).joinedload(Product.organization),
                      joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.source_document),
                      joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.source_revision_record),
                      joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.reproduction))
             .order_by(KnowledgeEntry.title, KnowledgeEntry.id))
    entries = db.execute(query).unique().scalars().all()
    store = ObjectStore()
    global_index = ["# 漏洞知识库索引", "", f"生成时间：{generation}", "", f"正式漏洞记录：{len(entries)}", ""]
    records: list[dict] = []
    browse: dict[str, dict[str, dict]] = {}

    for entry in entries:
        record_id = f"KB-{entry.id}"
        record_dir = staging / "records" / record_id
        for name in ("sources", "poc", "exp", "attachments"):
            (record_dir / name).mkdir(parents=True, exist_ok=True)
        products = []
        for relation in entry.products:
            product = relation.product
            organization = product.organization.name if product.organization else "未知厂商"
            item = {"organization": organization, "product": product.name, "openness": product.openness,
                    "category": _product_category(product.openness), "version": relation.version_expression,
                    "version_status": relation.version_status, "impact": relation.impact,
                    "match_confidence": relation.match_confidence}
            products.append(item)
            leaf = Path(item["category"]) / _slug(organization) / _slug(product.name) / _slug(relation.version_expression or "版本未知")
            browse.setdefault(leaf.as_posix(), {})[entry.id] = item
            if entry.special_topic:
                special_leaf = Path("特殊") / _slug(entry.special_topic)
                browse.setdefault(special_leaf.as_posix(), {})[entry.id] = item

        materials = [m for m in entry.materials if m.review_status == "approved"]
        report = [f"# {_md(entry.title)}", "", f"- KB ID：{entry.id}",
                  f"- CVE：{_md(entry.cve_id or '未关联')}", f"- 漏洞类型：{_md(entry.vuln_type or '未分类')}",
                  f"- 特殊主题：{_md(entry.special_topic or '普通产品漏洞')}", f"- 摘要：{_md(entry.summary or '—')}", "", "## 影响产品", ""]
        for item in products:
            report.append(f"- **{_md(item['organization'])} / {_md(item['product'])}** · {item['category']} · "
                          f"版本：{_md(item['version'] or '未知')} · {_md(item['version_status'])}")
            if item["impact"]:
                report.append(f"  - 影响：{_md(item['impact'])}")
        report.extend(["", "## 可复现材料", ""])
        reproduce = [f"# 复现过程 · {_md(entry.title)}", "", f"- 规范记录：{record_id}", ""]
        material_records = []

        for material in materials:
            source = material.source_document
            meta = source.metadata_json or {}
            raw_path = str(meta.get("path") or meta.get("file") or source.title)
            suffix = Path(raw_path).suffix.lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
                suffix = ".txt"
            folder = "poc" if material.material_kind == "poc" else "exp" if material.material_kind == "exp" else "attachments"
            artifact = record_dir / folder / f"{material.id}{suffix}"
            artifact.write_bytes(store.read(material.object_key))
            revision_row = material.source_revision_record
            sidecar = {"material_id": material.id, "kind": material.material_kind,
                       "source_url": material.source_url, "source_revision": material.source_revision,
                       "source_sha256": revision_row.sha256 if revision_row else material.sha256,
                       "sha256": material.sha256, "license_hint": material.license_hint,
                       "source_document_id": source.id}
            artifact.with_name(artifact.name + ".source.json").write_text(
                json.dumps(sidecar, ensure_ascii=False, indent=2), encoding="utf-8")
            source_note = record_dir / "sources" / f"source-{source.id}.md"
            source_note.write_text("\n".join([f"# 来源 · {_md(source.title)}", "",
                f"- 类型：{_md(source.source_key)}", f"- 外部 ID：{_md(source.external_id)}",
                f"- 原始链接：{_md_url(material.source_url)}", f"- 固定修订：{_md(material.source_revision or '未提供')}",
                f"- 材料 SHA-256：{material.sha256}", f"- 授权提示：{_md(material.license_hint or '待核对来源授权')}", ""]),
                encoding="utf-8")
            artifact_rel = artifact.relative_to(record_dir).as_posix()
            report.append(f"- **{_md(material.material_kind.upper())}** · {_md(material.evidence_grade)} · "
                          f"[材料]({artifact_rel}) · [来源说明](sources/{source_note.name}) · [原始页面]({_md_url(material.source_url)})")
            package = material.reproduction
            if package:
                applicable = ", ".join(f"{p['organization']} / {p['product']} ({p['version'] or '版本未知'})" for p in products)
                steps = (package.instructions or "—").replace(chr(96) * 3, "&#96;&#96;&#96;").splitlines()
                reproduce.extend([f"## {_md(material.material_kind.upper())} · {_md(material.language or '未知语言')}",
                                  f"- 适用产品：{_md(applicable or '未知产品')}",
                                  f"- 前置条件：{_md(package.prerequisites or '—')}", "", "### 操作步骤", ""])
                reproduce.extend("> " + _md(line) for line in steps)
                reproduce.extend(["", f"- 成功判据：{_md(package.success_criteria or '—')}",
                                  f"- 声明测试版本：{_md(package.tested_versions or '未声明')}",
                                  f"- 证据等级：{_md(material.evidence_grade)}", ""])
            material_records.append({**sidecar, "artifact": f"records/{record_id}/{artifact_rel}",
                                     "source_note": f"records/{record_id}/sources/{source_note.name}", "gates": material.gates})

        (record_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
        (record_dir / "reproduce.md").write_text("\n".join(reproduce) + "\n", encoding="utf-8")
        (record_dir / "field-guide.md").write_text("\n".join([f"# 实战复用卡 · {_md(entry.title)}", "",
            "在授权范围内先确认产品身份、适用版本、部署形态和成功判据。材料由 AI 审核，不代表团队独立实验验证。", ""]),
            encoding="utf-8")
        validation = {"id": entry.id, "status": entry.status, "materials": [
            {"id": m.id, "grade": m.evidence_grade, "review_status": m.review_status,
             "sha256": m.sha256, "gates": m.gates} for m in materials]}
        (record_dir / "validation.json").write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8")
        record_data = {"id": entry.id, "title": entry.title, "summary": entry.summary, "cve_id": entry.cve_id,
                       "cwe_ids": entry.cwe_ids, "vuln_type": entry.vuln_type, "special_topic": entry.special_topic,
                       "products": products, "materials": material_records}
        (record_dir / "record.json").write_text(json.dumps(record_data, ensure_ascii=False, indent=2), encoding="utf-8")
        report_path = record_dir / "report.md"
        report_rel = report_path.relative_to(staging).as_posix()
        first = products[0] if products else {"organization": "未知厂商", "product": "未知产品", "version": None}
        global_index.append(f"- [{_md(entry.title)}]({report_rel}) · {_md(first['organization'])} / "
                            f"{_md(first['product'])} / {_md(first.get('version') or '版本未知')} · {_md(entry.cve_id or entry.vuln_type or '漏洞')}")
        records.append({"id": entry.id, "title": entry.title, "path": report_rel,
                        "products": products, "material_ids": [m.id for m in materials]})

    for leaf_text, grouped in browse.items():
        leaf = staging / Path(leaf_text)
        leaf.mkdir(parents=True, exist_ok=True)
        overview = [f"# {_md(leaf.name)}", "", f"漏洞记录：{len(grouped)}", ""]
        for entry_id, item in sorted(grouped.items()):
            report_path = staging / "records" / f"KB-{entry_id}" / "report.md"
            link = _rel(leaf, report_path)
            stub_name = f"KB-{entry_id}.md"
            stub = [f"# KB-{entry_id}", "", f"- 厂商：{_md(item['organization'])}",
                    f"- 产品：{_md(item['product'])}", f"- 版本：{_md(item.get('version') or '未知')}",
                    f"- 完整记录：[查看报告]({link})", ""]
            (leaf / stub_name).write_text("\n".join(stub), encoding="utf-8")
            overview.append(f"- [{_md(item['product'])} · KB-{entry_id}]({stub_name}) · {_md(item.get('version') or '版本未知')}")
        (leaf / "index.md").write_text("\n".join(overview) + "\n", encoding="utf-8")

    (staging / "index.md").write_text("\n".join(global_index) + "\n", encoding="utf-8")
    (staging / "index.json").write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    file_hashes = []
    for path in sorted(staging.rglob("*")):
        if path.is_file():
            content = path.read_bytes()
            file_hashes.append({"path": path.relative_to(staging).as_posix(),
                                "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)})
    manifest = {"schema_version": "1.0", "generation": generation,
                "created_at": datetime.now(timezone.utc).isoformat(), "record_count": len(records), "files": file_hashes}
    (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    final = settings.export_dir / generation
    staging.replace(final)
    temp = settings.export_dir / f".current-{generation}.tmp"
    temp.write_text(json.dumps({"generation": generation, "path": generation}, ensure_ascii=False), encoding="utf-8")
    temp.replace(settings.export_dir / "current.json")
    return final
