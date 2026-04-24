#!/usr/bin/env python3
"""Requirement coverage checker for basic-snmp-agent.

Verifies that every requirement from all "impl"-phase RFCs is covered by:
  - at least one ``Implements: REQ-XXXX`` annotation in a ``.rs`` file,
  - at least one ``Verifies: REQ-XXXX`` annotation in a ``.rs`` file, and
  - at least one ``@REQ-XXXX`` tag in a ``.feature`` file,

unless the requirement is explicitly exempted in ``gov/req-coverage-gaps.toml``.

Requires Python 3.11+ (stdlib tomllib) or Python 3.10 with the ``tomli``
package installed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-reuse-def]
    except ImportError as exc:
        raise ImportError(
            "Python 3.11+ is required, or install the 'tomli' package "
            "(pip install tomli) when running Python 3.10."
        ) from exc


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

# Coverage kinds used throughout the checker.
COVERAGE_KINDS: tuple[str, ...] = ("code", "rust_test", "behave_test")

# Maps a requirement ID such as "REQ-0034" to the set of coverage kinds
# that are exempted from checking.
ExemptionMap = dict[str, set[str]]

# Maps a requirement ID to the set of coverage kinds present.
CoverageMap = dict[str, set[str]]


class ImplementedRfc(NamedTuple):
    """Pairs an RFC's filesystem directory with its parsed TOML record."""

    rfc_dir: Path
    record: dict


# ---------------------------------------------------------------------------
# Project-root detection
# ---------------------------------------------------------------------------


def find_project_root(start: Path) -> Path:
    """Walk upward from *start* until a directory containing ``gov/rfc/`` is found.

    Raises ``FileNotFoundError`` if no such directory exists up to the
    filesystem root.
    """
    candidate = start.resolve()
    while True:
        if (candidate / "gov" / "rfc").is_dir():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            raise FileNotFoundError(
                f"Could not find a project root (directory containing 'gov/rfc/') "
                f"starting from {start}"
            )
        candidate = parent


# ---------------------------------------------------------------------------
# RFC and requirement loading
# ---------------------------------------------------------------------------


def load_implemented_rfcs(
    gov_dir: Path,
    force_rfc_ids: set[str] | None = None,
) -> list[ImplementedRfc]:
    """Return an ``ImplementedRfc`` for every RFC whose phase is ``test`` or ``stable``.

    Tracing is only enforced once implementation is complete. RFCs in the
    ``spec`` or ``impl`` phase are still being written and are excluded,
    unless their ID is listed in *force_rfc_ids*, in which case they are
    included regardless of phase.
    """
    rfc_root = gov_dir / "rfc"
    implemented: list[ImplementedRfc] = []
    for rfc_dir in sorted(rfc_root.iterdir()):
        rfc_toml_path = rfc_dir / "rfc.toml"
        if not rfc_toml_path.is_file():
            continue
        with rfc_toml_path.open("rb") as toml_file:
            rfc_record = tomllib.load(toml_file)
        rfc_id = rfc_record["govctl"]["id"]
        phase_qualifies = rfc_record["govctl"].get("phase") in ("test", "stable")
        force_included = force_rfc_ids is not None and rfc_id in force_rfc_ids
        if phase_qualifies or force_included:
            implemented.append(ImplementedRfc(rfc_dir=rfc_dir, record=rfc_record))
    return implemented


def extract_req_ids_from_clause_text(clause_text: str) -> set[str]:
    """Return all ``REQ-XXXX`` identifiers found inside ``[REQ-XXXX]`` tags."""
    # Only tagged requirements (inside square brackets) are normative obligations
    # that must be tracked; bare mentions elsewhere are informative.
    bracketed_tags = re.findall(r"\[REQ-\d{4}\]", clause_text)
    return {tag[1:-1] for tag in bracketed_tags}  # strip the [ ] delimiters


def collect_requirements_from_rfc(rfc: ImplementedRfc) -> set[str]:
    """Return all requirement IDs mentioned in the clauses of one RFC."""
    req_ids: set[str] = set()
    for section in rfc.record.get("sections", []):
        for clause_relative_path in section.get("clauses", []):
            clause_path = rfc.rfc_dir / clause_relative_path
            with clause_path.open("rb") as toml_file:
                clause_toml = tomllib.load(toml_file)
            req_ids |= extract_req_ids_from_clause_text(clause_toml.get("content", {}).get("text", ""))
    return req_ids


def collect_all_requirements(implemented_rfcs: list[ImplementedRfc]) -> set[str]:
    """Return the union of all requirement IDs across all implemented RFCs."""
    all_req_ids: set[str] = set()
    for rfc_record in implemented_rfcs:
        all_req_ids |= collect_requirements_from_rfc(rfc_record)
    return all_req_ids


def find_duplicate_req_ids(
    implemented_rfcs: list[ImplementedRfc],
) -> dict[str, list[str]]:
    """Return a map of duplicate REQ ID → list of RFC IDs that define it.

    A duplicate is a REQ ID that appears in the clauses of more than one
    implemented RFC. Repeated appearances within a single RFC's own clauses are
    not reported because clause authoring sometimes legitimately references the
    same ID in multiple places within the same RFC.
    """
    # Collect one set of req IDs per RFC so intra-RFC repetition is collapsed.
    per_rfc_req_ids: list[tuple[str, set[str]]] = [
        (rfc.record["govctl"]["id"], collect_requirements_from_rfc(rfc))
        for rfc in implemented_rfcs
    ]

    # Count how many distinct RFCs claim each req ID.
    req_id_to_rfc_ids: dict[str, list[str]] = {}
    for rfc_id, req_ids in per_rfc_req_ids:
        for req_id in req_ids:
            req_id_to_rfc_ids.setdefault(req_id, []).append(rfc_id)

    return {
        req_id: rfc_ids
        for req_id, rfc_ids in req_id_to_rfc_ids.items()
        if len(rfc_ids) > 1
    }


# ---------------------------------------------------------------------------
# Coverage scanning
# ---------------------------------------------------------------------------


def extract_req_ids_from_annotation_line(line: str, marker: str) -> set[str]:
    """Return all ``REQ-XXXX`` IDs from a line that contains *marker*.

    Handles comma-separated lists such as::

        // Implements: REQ-0034, REQ-0035
        /// Verifies: REQ-0043
    """
    if marker not in line:
        return set()
    return set(re.findall(r"REQ-\d{4}", line))


def scan_rust_file_for_annotations(rust_file: Path) -> tuple[set[str], set[str]]:
    """Return ``(implements_ids, verifies_ids)`` found in a single ``.rs`` file."""
    implements_ids: set[str] = set()
    verifies_ids: set[str] = set()
    for line in rust_file.read_text(encoding="utf-8").splitlines():
        implements_ids |= extract_req_ids_from_annotation_line(line, "Implements:")
        verifies_ids |= extract_req_ids_from_annotation_line(line, "Verifies:")
    return implements_ids, verifies_ids


def scan_rust_coverage(project_root: Path) -> tuple[set[str], set[str]]:
    """Scan all ``.rs`` files under *project_root* for coverage annotations.

    Returns ``(code_coverage_ids, rust_test_coverage_ids)``.
    """
    code_coverage_ids: set[str] = set()
    rust_test_coverage_ids: set[str] = set()
    for rust_file in project_root.rglob("*.rs"):
        implements_ids, verifies_ids = scan_rust_file_for_annotations(rust_file)
        code_coverage_ids |= implements_ids
        rust_test_coverage_ids |= verifies_ids
    return code_coverage_ids, rust_test_coverage_ids


def scan_feature_file_for_req_tags(feature_file: Path) -> set[str]:
    """Return all ``REQ-XXXX`` IDs referenced via ``@REQ-XXXX`` tags."""
    behave_req_ids: set[str] = set()
    for line in feature_file.read_text(encoding="utf-8").splitlines():
        # Tags appear on lines such as "@REQ-0034 @REQ-0035"; extract all on
        # the line so that multi-tag lines are handled correctly.
        if "@REQ-" in line:
            behave_req_ids |= set(re.findall(r"REQ-\d{4}", line))
    return behave_req_ids


def scan_behave_coverage(project_root: Path) -> set[str]:
    """Return all requirement IDs covered by ``@REQ-XXXX`` tags in feature files."""
    features_dir = project_root / "tests" / "system" / "features"
    behave_req_ids: set[str] = set()
    # rglob on a non-existent directory yields nothing, which is the intended
    # behaviour for projects that have not yet added any feature files.
    for feature_file in features_dir.rglob("*.feature"):
        behave_req_ids |= scan_feature_file_for_req_tags(feature_file)
    return behave_req_ids


# ---------------------------------------------------------------------------
# Exemption loading
# ---------------------------------------------------------------------------


def load_exemptions(gov_dir: Path) -> ExemptionMap:
    """Parse ``gov/req-coverage-gaps.toml`` and return an exemption map.

    The returned dict maps a requirement ID (e.g. ``"REQ-0039"``) to the set
    of coverage kinds that are explicitly waived for that requirement.

    Raises ``ValueError`` if any ``missing`` entry contains an unrecognised
    coverage kind, catching typos such as ``"behave_tests"`` early.
    """
    gap_file = gov_dir / "req-coverage-gaps.toml"
    if not gap_file.is_file():
        return {}

    with gap_file.open("rb") as toml_file:
        parsed_gaps = tomllib.load(toml_file)

    exemptions: ExemptionMap = {}
    for gap_entry in parsed_gaps.get("gap", []):
        req_id: str = gap_entry["req"]
        missing_kinds: list[str] = gap_entry.get("missing", [])
        for kind in missing_kinds:
            if kind not in COVERAGE_KINDS:
                raise ValueError(
                    f"Unknown coverage kind '{kind}' for '{req_id}' in "
                    f"req-coverage-gaps.toml. Valid kinds: {COVERAGE_KINDS}"
                )
        exemptions[req_id] = set(missing_kinds)
    return exemptions


# ---------------------------------------------------------------------------
# Coverage checking
# ---------------------------------------------------------------------------


def build_coverage_map(
    code_ids: set[str],
    rust_test_ids: set[str],
    behave_ids: set[str],
) -> CoverageMap:
    """Combine the three coverage sets into a single map of ID → present kinds."""
    all_mentioned_ids = code_ids | rust_test_ids | behave_ids
    coverage: CoverageMap = {}
    for req_id in all_mentioned_ids:
        present_kinds: set[str] = set()
        if req_id in code_ids:
            present_kinds.add("code")
        if req_id in rust_test_ids:
            present_kinds.add("rust_test")
        if req_id in behave_ids:
            present_kinds.add("behave_test")
        coverage[req_id] = present_kinds
    return coverage


def check_coverage(
    required_req_ids: set[str],
    coverage_map: CoverageMap,
    exemptions: ExemptionMap,
) -> dict[str, list[str]]:
    """Return a dict mapping each failing REQ ID to its list of missing kinds.

    A coverage kind is considered missing when the requirement has no annotation
    of that kind and the kind is not listed in the requirement's exemptions.
    """
    failures: dict[str, list[str]] = {}
    for req_id in sorted(required_req_ids):
        present_kinds = coverage_map.get(req_id, set())
        exempted_kinds = exemptions.get(req_id, set())
        missing_kinds = [
            kind
            for kind in COVERAGE_KINDS
            if kind not in present_kinds and kind not in exempted_kinds
        ]
        if missing_kinds:
            failures[req_id] = missing_kinds
    return failures


def find_orphaned_annotations(
    annotated_ids: set[str],
    required_ids: set[str],
) -> set[str]:
    """Return IDs that appear in annotations but are not defined in any implemented RFC.

    Orphaned annotations arise when a REQ ID is referenced in an
    ``Implements:``, ``Verifies:``, or ``@REQ-`` tag but has no corresponding
    ``[REQ-XXXX]`` clause tag in any implemented RFC — for example, after a
    requirement is removed from an RFC without cleaning up its annotations.
    """
    return annotated_ids - required_ids


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_check(
    project_root: Path,
    strict: bool = False,
    force_rfc_ids: set[str] | None = None,
) -> int:
    """Execute the full coverage check and print a summary.

    When *strict* is ``True``, annotations that reference a REQ ID not defined
    in any implemented RFC are also reported and cause a non-zero exit.

    *force_rfc_ids*, if given, is a set of RFC IDs to include regardless of
    their current phase (useful for checking in-progress RFCs).

    Returns the exit code: 0 for pass, 1 for failure.
    """
    gov_dir = project_root / "gov"

    implemented_rfcs = load_implemented_rfcs(gov_dir, force_rfc_ids=force_rfc_ids)
    rfc_count = len(implemented_rfcs)
    print(f"Checking requirement coverage for {rfc_count} implemented RFC(s)...")

    required_req_ids = collect_all_requirements(implemented_rfcs)
    print(f"Found {len(required_req_ids)} requirements in implemented RFCs.")
    print()

    # Duplicate REQ IDs across RFCs are a governance error; always warn.
    duplicates = find_duplicate_req_ids(implemented_rfcs)
    for req_id, defining_rfc_ids in sorted(duplicates.items()):
        rfc_list = ", ".join(defining_rfc_ids)
        print(f"WARNING {req_id}: defined in multiple RFCs: {rfc_list}")
    if duplicates:
        print()

    code_ids, rust_test_ids = scan_rust_coverage(project_root)
    behave_ids = scan_behave_coverage(project_root)
    coverage_map = build_coverage_map(code_ids, rust_test_ids, behave_ids)

    exemptions = load_exemptions(gov_dir)

    failures = check_coverage(required_req_ids, coverage_map, exemptions)

    exit_code = 0

    if failures:
        for req_id, missing_kinds in sorted(failures.items()):
            missing_label = ", ".join(missing_kinds)
            print(f"FAIL {req_id}: missing {missing_label}")
        print()
        print(f"Coverage check FAILED: {len(failures)} requirement(s) have gaps.")
        exit_code = 1
    else:
        print(
            f"Coverage check PASSED: all {len(required_req_ids)} requirements fully covered."
        )

    if strict:
        annotated_ids = code_ids | rust_test_ids | behave_ids
        orphaned_ids = find_orphaned_annotations(annotated_ids, required_req_ids)
        if orphaned_ids:
            print()
            for req_id in sorted(orphaned_ids):
                print(
                    f"ORPHAN {req_id}: referenced in annotations but not defined "
                    f"in any implemented RFC"
                )
            print()
            print(f"Strict check FAILED: {len(orphaned_ids)} orphaned annotation(s).")
            exit_code = 1

    return exit_code


def main() -> None:
    """Parse CLI arguments and run the coverage check."""
    parser = argparse.ArgumentParser(
        description="Check that every requirement in implemented RFCs has "
        "code, unit test, and Behave scenario coverage."
    )
    parser.add_argument(
        "--root",
        metavar="PATH",
        type=Path,
        default=None,
        help="Override the project root directory (default: auto-detected by "
        "walking up from the script location until a 'gov/rfc/' directory is found).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Also fail if any annotation references a REQ ID not defined in "
        "any implemented RFC (orphaned annotation check).",
    )
    parser.add_argument(
        "--rfc",
        metavar="RFC_ID",
        action="append",
        dest="force_rfc_ids",
        default=None,
        help="Include this RFC in the check regardless of its phase. "
        "May be repeated to force multiple RFCs (e.g. --rfc RFC-0002 --rfc RFC-0003).",
    )
    args = parser.parse_args()

    if args.root is not None:
        project_root = args.root.resolve()
    else:
        project_root = find_project_root(Path(__file__).parent)

    force_rfc_ids = set(args.force_rfc_ids) if args.force_rfc_ids else None
    sys.exit(run_check(project_root, strict=args.strict, force_rfc_ids=force_rfc_ids))


if __name__ == "__main__":
    main()
