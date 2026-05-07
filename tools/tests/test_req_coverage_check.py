"""Pytest unit tests for req_coverage_check.py.

Each test uses only in-memory or tmp_path data so the suite is independent of
the real project files.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

# Allow importing the script from the parent directory without installing it.
sys.path.insert(0, str(Path(__file__).parent.parent))

from req_coverage_check import (  # noqa: E402  # pylint: disable=wrong-import-position
    COVERAGE_KINDS,
    ImplementedRfc,
    build_coverage_map,
    check_coverage,
    collect_all_requirements,
    collect_requirements_from_rfc,
    extract_req_ids_from_annotation_line,
    extract_req_ids_from_clause_text,
    find_duplicate_req_ids,
    find_orphaned_annotations,
    find_project_root,
    load_exemptions,
    load_implemented_rfcs,
    run_check,
    scan_behave_coverage,
    scan_feature_file_for_req_tags,
    scan_rust_coverage,
    scan_rust_file_for_annotations,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rfc_dir(
    tmp_path: Path,
    rfc_id: str,
    phase: str,
    clauses: list[dict[str, str]],
) -> Path:
    """Create a minimal RFC directory structure under *tmp_path* and return it."""
    rfc_dir = tmp_path / "gov" / "rfc" / rfc_id
    rfc_dir.mkdir(parents=True)
    clauses_dir = rfc_dir / "clauses"
    clauses_dir.mkdir()

    clause_paths: list[str] = []
    for clause_content in clauses:
        clause_filename = f"{clause_content['clause_id']}.toml"
        # Clause IDs and text must not contain TOML-special characters
        # (triple-quotes, backslash sequences) as this TOML is hand-rolled.
        toml_content = (
            f'[govctl]\nid = "{clause_content["clause_id"]}"\n\n'
            f'[content]\ntext = """\n{clause_content["text"]}\n"""\n'
        )
        (clauses_dir / clause_filename).write_text(toml_content, encoding="utf-8")
        clause_paths.append(f"clauses/{clause_filename}")

    # RFC IDs and phase strings must not contain TOML-special characters
    # (triple-quotes, backslash sequences) as this TOML is hand-rolled.
    lines = [
        "[govctl]\n",
        f'id = "{rfc_id}"\n',
        f'phase = "{phase}"\n',
        "\n",
        "[[sections]]\n",
        'title = "Spec"\n',
        "clauses = [",
        ", ".join(f'"{p}"' for p in clause_paths),
        "]\n",
    ]
    (rfc_dir / "rfc.toml").write_text("".join(lines), encoding="utf-8")
    return rfc_dir


def make_gap_toml(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    """Write a ``gov/req-coverage-gaps.toml`` file and return its path."""
    gov_dir = tmp_path / "gov"
    gov_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for entry in entries:
        lines.append("[[gap]]")
        lines.append(f'req     = "{entry["req"]}"')
        missing_quoted = ", ".join(f'"{kind}"' for kind in entry.get("missing", []))
        lines.append(f"missing = [{missing_quoted}]")
        lines.append(f'rationale = "{entry.get("rationale", "")}"')
        lines.append("")
    (gov_dir / "req-coverage-gaps.toml").write_text("\n".join(lines), encoding="utf-8")
    return gov_dir / "req-coverage-gaps.toml"


def _load_toml(path: Path) -> dict[str, Any]:
    """Open *path* in binary mode and return the parsed TOML document."""
    with path.open("rb") as toml_file:
        return tomllib.load(toml_file)


# ---------------------------------------------------------------------------
# find_project_root
# ---------------------------------------------------------------------------


class TestFindProjectRoot:
    def test_finds_root_when_gov_rfc_dir_exists(self, tmp_path: Path) -> None:
        (tmp_path / "gov" / "rfc").mkdir(parents=True)
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)

        found_root = find_project_root(nested)

        assert found_root == tmp_path

    def test_returns_root_itself_when_gov_rfc_is_in_start_dir(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "gov" / "rfc").mkdir(parents=True)

        found_root = find_project_root(tmp_path)

        assert found_root == tmp_path

    def test_raises_when_no_gov_rfc_dir_found(self, tmp_path: Path) -> None:
        # A directory with no ancestor containing "gov/rfc/"
        isolated = tmp_path / "isolated"
        isolated.mkdir()

        with pytest.raises(FileNotFoundError, match="project root"):
            find_project_root(isolated)


# ---------------------------------------------------------------------------
# Requirement extraction from clause text
# ---------------------------------------------------------------------------


class TestExtractReqIdsFromClauseText:
    def test_extracts_single_req_tag(self) -> None:
        clause_text = "[REQ-0001] The agent MUST do something."

        req_ids = extract_req_ids_from_clause_text(clause_text)

        assert req_ids == {"REQ-0001"}

    def test_extracts_multiple_req_tags(self) -> None:
        clause_text = (
            "[REQ-0034] The library MUST expose a public function.\n"
            "[REQ-0035] The function MUST block until delivery.\n"
        )

        req_ids = extract_req_ids_from_clause_text(clause_text)

        assert req_ids == {"REQ-0034", "REQ-0035"}

    def test_ignores_bare_req_references_outside_brackets(self) -> None:
        # A mention like "see REQ-0001" in rationale text is not a normative tag.
        clause_text = "See REQ-0001 for context. [REQ-0002] The agent MUST do X."

        req_ids = extract_req_ids_from_clause_text(clause_text)

        assert req_ids == {"REQ-0002"}

    def test_returns_empty_set_for_text_with_no_req_tags(self) -> None:
        clause_text = "This is an informative section with no requirements."

        req_ids = extract_req_ids_from_clause_text(clause_text)

        assert req_ids == set()

    def test_handles_empty_text(self) -> None:
        assert extract_req_ids_from_clause_text("") == set()


# ---------------------------------------------------------------------------
# Annotation line parsing
# ---------------------------------------------------------------------------


class TestExtractReqIdsFromAnnotationLine:
    def test_extracts_single_id_from_implements_line(self) -> None:
        line = "/// Implements: REQ-0048"

        req_ids = extract_req_ids_from_annotation_line(line, "Implements:")

        assert req_ids == {"REQ-0048"}

    def test_extracts_multiple_comma_separated_ids_from_implements_line(self) -> None:
        line = "/// Implements: REQ-0034, REQ-0035"

        req_ids = extract_req_ids_from_annotation_line(line, "Implements:")

        assert req_ids == {"REQ-0034", "REQ-0035"}

    def test_extracts_single_id_from_verifies_line(self) -> None:
        line = "        // Verifies: REQ-0043"

        req_ids = extract_req_ids_from_annotation_line(line, "Verifies:")

        assert req_ids == {"REQ-0043"}

    def test_extracts_multiple_ids_from_verifies_line(self) -> None:
        line = "        // Verifies: REQ-0035, REQ-0036, REQ-0044, REQ-0047"

        req_ids = extract_req_ids_from_annotation_line(line, "Verifies:")

        assert req_ids == {"REQ-0035", "REQ-0036", "REQ-0044", "REQ-0047"}

    def test_returns_empty_set_when_marker_absent(self) -> None:
        line = "let foo = bar;"

        req_ids = extract_req_ids_from_annotation_line(line, "Implements:")

        assert req_ids == set()

    def test_does_not_match_verifies_marker_on_implements_line(self) -> None:
        line = "/// Implements: REQ-0048"

        req_ids = extract_req_ids_from_annotation_line(line, "Verifies:")

        assert req_ids == set()


# ---------------------------------------------------------------------------
# Feature file tag scanning
# ---------------------------------------------------------------------------


class TestScanFeatureFileForReqTags:
    def test_extracts_single_tag(self, tmp_path: Path) -> None:
        feature_file = tmp_path / "example.feature"
        feature_file.write_text(
            "Feature: Example\n\n  @REQ-0034\n  Scenario: First\n    Given something\n",
            encoding="utf-8",
        )

        req_ids = scan_feature_file_for_req_tags(feature_file)

        assert req_ids == {"REQ-0034"}

    def test_extracts_multiple_tags_from_same_line(self, tmp_path: Path) -> None:
        feature_file = tmp_path / "example.feature"
        feature_file.write_text(
            "  @REQ-0034 @REQ-0035 @REQ-0036\n  Scenario: Multi\n",
            encoding="utf-8",
        )

        req_ids = scan_feature_file_for_req_tags(feature_file)

        assert req_ids == {"REQ-0034", "REQ-0035", "REQ-0036"}

    def test_extracts_tags_across_multiple_scenarios(self, tmp_path: Path) -> None:
        feature_file = tmp_path / "example.feature"
        feature_file.write_text(
            "  @REQ-0034\n  Scenario: First\n\n  @REQ-0040\n  Scenario: Second\n",
            encoding="utf-8",
        )

        req_ids = scan_feature_file_for_req_tags(feature_file)

        assert req_ids == {"REQ-0034", "REQ-0040"}

    def test_returns_empty_set_for_feature_with_no_req_tags(
        self, tmp_path: Path
    ) -> None:
        feature_file = tmp_path / "example.feature"
        feature_file.write_text(
            "Feature: No reqs\n\n  Scenario: Tagless\n    Given something\n",
            encoding="utf-8",
        )

        req_ids = scan_feature_file_for_req_tags(feature_file)

        assert req_ids == set()


# ---------------------------------------------------------------------------
# Exemption loading
# ---------------------------------------------------------------------------


class TestLoadExemptions:
    def test_loads_single_exemption(self, tmp_path: Path) -> None:
        make_gap_toml(
            tmp_path,
            [
                {
                    "req": "REQ-0039",
                    "missing": ["behave_test"],
                    "rationale": "compile-time",
                }
            ],
        )
        gov_dir = tmp_path / "gov"

        exemptions = load_exemptions(gov_dir)

        assert "REQ-0039" in exemptions
        assert exemptions["REQ-0039"] == {"behave_test"}

    def test_loads_multiple_exemptions(self, tmp_path: Path) -> None:
        make_gap_toml(
            tmp_path,
            [
                {"req": "REQ-0039", "missing": ["behave_test"], "rationale": "x"},
                {"req": "REQ-0043", "missing": ["behave_test"], "rationale": "y"},
                {
                    "req": "REQ-0046",
                    "missing": ["rust_test", "behave_test"],
                    "rationale": "z",
                },
            ],
        )
        gov_dir = tmp_path / "gov"

        exemptions = load_exemptions(gov_dir)

        assert exemptions["REQ-0039"] == {"behave_test"}
        assert exemptions["REQ-0043"] == {"behave_test"}
        assert exemptions["REQ-0046"] == {"rust_test", "behave_test"}

    def test_returns_empty_map_when_gap_file_absent(self, tmp_path: Path) -> None:
        gov_dir = tmp_path / "gov"
        gov_dir.mkdir()

        exemptions = load_exemptions(gov_dir)

        assert exemptions == {}

    def test_raises_on_unknown_coverage_kind_in_gap_file(self, tmp_path: Path) -> None:
        # "behave_tests" is a typo for "behave_test"; the loader must reject it.
        make_gap_toml(
            tmp_path,
            [{"req": "REQ-0039", "missing": ["behave_tests"], "rationale": "typo"}],
        )
        gov_dir = tmp_path / "gov"

        with pytest.raises(ValueError, match="behave_tests"):
            load_exemptions(gov_dir)


# ---------------------------------------------------------------------------
# Coverage-check logic
# ---------------------------------------------------------------------------


class TestCheckCoverage:
    def _all_coverage(self, req_id: str) -> dict[str, set[str]]:
        return {req_id: set(COVERAGE_KINDS)}

    def test_req_with_all_three_coverage_kinds_passes(self) -> None:
        required = {"REQ-0001"}
        coverage_map = self._all_coverage("REQ-0001")

        failures = check_coverage(required, coverage_map, exemptions={})

        assert failures == {}

    def test_req_missing_all_three_kinds_fails(self) -> None:
        required = {"REQ-0099"}

        failures = check_coverage(required, coverage_map={}, exemptions={})

        assert "REQ-0099" in failures
        assert set(failures["REQ-0099"]) == {"code", "rust_test", "behave_test"}

    def test_req_missing_one_kind_fails_for_that_kind_only(self) -> None:
        required = {"REQ-0001"}
        coverage_map = {"REQ-0001": {"code", "rust_test"}}  # behave_test absent

        failures = check_coverage(required, coverage_map, exemptions={})

        assert failures["REQ-0001"] == ["behave_test"]

    def test_req_with_exempted_missing_kind_passes(self) -> None:
        required = {"REQ-0039"}
        coverage_map = {
            "REQ-0039": {"code", "rust_test"}
        }  # behave_test absent but exempted
        exemptions = {"REQ-0039": {"behave_test"}}

        failures = check_coverage(required, coverage_map, exemptions)

        assert failures == {}

    def test_req_with_all_uncovered_kinds_exempted_passes(self) -> None:
        required = {"REQ-0046"}
        coverage_map = {
            "REQ-0046": {"code"}
        }  # rust_test and behave_test absent but exempted
        exemptions = {"REQ-0046": {"rust_test", "behave_test"}}

        failures = check_coverage(required, coverage_map, exemptions)

        assert failures == {}

    def test_req_with_exemption_and_still_missing_non_exempted_kind_fails(self) -> None:
        required = {"REQ-0010"}
        coverage_map = {"REQ-0010": {"code"}}  # rust_test absent (not exempted)
        exemptions = {"REQ-0010": {"behave_test"}}

        failures = check_coverage(required, coverage_map, exemptions)

        assert "REQ-0010" in failures
        assert "rust_test" in failures["REQ-0010"]
        assert "behave_test" not in failures["REQ-0010"]

    def test_only_requirements_in_required_set_are_checked(self) -> None:
        # REQ-0002 is annotated but not in the RFC — must not appear in failures.
        required = {"REQ-0001"}
        coverage_map = {
            "REQ-0001": set(COVERAGE_KINDS),
            "REQ-0002": set(),  # totally uncovered but not required
        }

        failures = check_coverage(required, coverage_map, exemptions={})

        assert failures == {}


# ---------------------------------------------------------------------------
# RFC loading
# ---------------------------------------------------------------------------


class TestLoadImplementedRfcs:
    def test_loads_rfc_in_test_phase(self, tmp_path: Path) -> None:
        make_rfc_dir(tmp_path, "RFC-0001", "test", [])

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        rfc_ids = [rfc.record["govctl"]["id"] for rfc in implemented_rfcs]
        assert "RFC-0001" in rfc_ids

    def test_loads_rfc_in_stable_phase(self, tmp_path: Path) -> None:
        make_rfc_dir(tmp_path, "RFC-0001", "stable", [])

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        rfc_ids = [rfc.record["govctl"]["id"] for rfc in implemented_rfcs]
        assert "RFC-0001" in rfc_ids

    def test_ignores_rfc_in_impl_phase(self, tmp_path: Path) -> None:
        # impl means implementation is in progress — tracing is not yet enforced.
        make_rfc_dir(tmp_path, "RFC-0002", "impl", [])

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        rfc_ids = [rfc.record["govctl"]["id"] for rfc in implemented_rfcs]
        assert "RFC-0002" not in rfc_ids

    def test_ignores_rfc_in_spec_and_draft_phases(self, tmp_path: Path) -> None:
        make_rfc_dir(tmp_path, "RFC-0003", "spec", [])
        make_rfc_dir(tmp_path, "RFC-0004", "draft", [])

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        rfc_ids = [rfc.record["govctl"]["id"] for rfc in implemented_rfcs]
        assert "RFC-0003" not in rfc_ids
        assert "RFC-0004" not in rfc_ids

    def test_loads_multiple_rfcs_in_test_and_stable_phases(
        self, tmp_path: Path
    ) -> None:
        make_rfc_dir(tmp_path, "RFC-0001", "test", [])
        make_rfc_dir(tmp_path, "RFC-0002", "stable", [])
        make_rfc_dir(tmp_path, "RFC-0003", "impl", [])

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        assert len(implemented_rfcs) == 2


class TestCollectRequirementsFromRfc:
    def test_collects_req_ids_from_all_clauses(self, tmp_path: Path) -> None:
        clauses = [
            {
                "clause_id": "C-TRANSPORT",
                "text": "[REQ-0004] MUST listen on TLS.\n[REQ-0005] MUST bind port 10161.",
            },
            {
                "clause_id": "C-AUTH",
                "text": "[REQ-0015] MUST use X.509 certs.\n[REQ-0016] MUST verify hostname.",
            },
        ]
        rfc_dir = make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)

        rfc_record = _load_toml(rfc_dir / "rfc.toml")
        rfc = ImplementedRfc(rfc_dir=rfc_dir, record=rfc_record)

        req_ids = collect_requirements_from_rfc(rfc)

        assert req_ids == {"REQ-0004", "REQ-0005", "REQ-0015", "REQ-0016"}

    def test_returns_empty_set_for_rfc_with_no_tagged_requirements(
        self, tmp_path: Path
    ) -> None:
        clauses = [
            {"clause_id": "C-SUMMARY", "text": "This is an informative summary."},
        ]
        rfc_dir = make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)
        rfc_record = _load_toml(rfc_dir / "rfc.toml")
        rfc = ImplementedRfc(rfc_dir=rfc_dir, record=rfc_record)

        req_ids = collect_requirements_from_rfc(rfc)

        assert req_ids == set()


class TestCollectAllRequirements:
    def test_unions_requirements_from_multiple_rfcs(self, tmp_path: Path) -> None:
        clauses_rfc1 = [
            {"clause_id": "C-TRANSPORT", "text": "[REQ-0001] MUST listen."},
        ]
        clauses_rfc2 = [
            {"clause_id": "C-AUTH", "text": "[REQ-0002] MUST authenticate."},
        ]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses_rfc1)
        make_rfc_dir(tmp_path, "RFC-0002", "test", clauses_rfc2)

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")
        all_req_ids = collect_all_requirements(implemented_rfcs)

        assert all_req_ids == {"REQ-0001", "REQ-0002"}

    def test_returns_empty_set_when_no_rfcs_have_requirements(
        self, tmp_path: Path
    ) -> None:
        clauses = [{"clause_id": "C-SUMMARY", "text": "Informative only."}]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)

        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")
        all_req_ids = collect_all_requirements(implemented_rfcs)

        assert all_req_ids == set()


# ---------------------------------------------------------------------------
# Rust file scanning
# ---------------------------------------------------------------------------


class TestScanRustFileForAnnotations:
    def test_extracts_implements_and_verifies_from_same_file(
        self, tmp_path: Path
    ) -> None:
        rust_file = tmp_path / "lib.rs"
        rust_file.write_text(
            "/// Implements: REQ-0034, REQ-0035\npub fn send_trap() {}\n\n"
            "        // Verifies: REQ-0034\n        assert!(true);\n",
            encoding="utf-8",
        )

        implements_ids, verifies_ids = scan_rust_file_for_annotations(rust_file)

        assert implements_ids == {"REQ-0034", "REQ-0035"}
        assert verifies_ids == {"REQ-0034"}

    def test_returns_empty_sets_for_file_with_no_annotations(
        self, tmp_path: Path
    ) -> None:
        rust_file = tmp_path / "empty.rs"
        rust_file.write_text("fn main() {}\n", encoding="utf-8")

        implements_ids, verifies_ids = scan_rust_file_for_annotations(rust_file)

        assert implements_ids == set()
        assert verifies_ids == set()


class TestScanRustCoverage:
    def test_collects_annotations_from_multiple_rust_files(
        self, tmp_path: Path
    ) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(
            "/// Implements: REQ-0001\n// Verifies: REQ-0001\n",
            encoding="utf-8",
        )
        sub_dir = src_dir / "sub"
        sub_dir.mkdir()
        (sub_dir / "module.rs").write_text(
            "/// Implements: REQ-0002\n// Verifies: REQ-0002\n",
            encoding="utf-8",
        )

        code_ids, test_ids = scan_rust_coverage(tmp_path)

        assert code_ids == {"REQ-0001", "REQ-0002"}
        assert test_ids == {"REQ-0001", "REQ-0002"}


# ---------------------------------------------------------------------------
# Behave coverage scanning
# ---------------------------------------------------------------------------


class TestScanBehaveCoverage:
    def test_collects_tags_from_feature_files(self, tmp_path: Path) -> None:
        features_dir = tmp_path / "tests" / "system" / "features"
        features_dir.mkdir(parents=True)
        (features_dir / "traps.feature").write_text(
            "  @REQ-0034 @REQ-0035\n  Scenario: First\n",
            encoding="utf-8",
        )
        (features_dir / "transport.feature").write_text(
            "  @REQ-0004\n  Scenario: Second\n",
            encoding="utf-8",
        )

        behave_ids = scan_behave_coverage(tmp_path)

        assert behave_ids == {"REQ-0034", "REQ-0035", "REQ-0004"}

    def test_returns_empty_set_when_features_dir_is_absent(
        self, tmp_path: Path
    ) -> None:
        behave_ids = scan_behave_coverage(tmp_path)

        assert behave_ids == set()


# ---------------------------------------------------------------------------
# build_coverage_map
# ---------------------------------------------------------------------------


class TestBuildCoverageMap:
    def test_combines_all_three_coverage_sets(self) -> None:
        code_ids = {"REQ-0001", "REQ-0002"}
        rust_test_ids = {"REQ-0001"}
        behave_ids = {"REQ-0001", "REQ-0002"}

        coverage_map = build_coverage_map(code_ids, rust_test_ids, behave_ids)

        assert coverage_map["REQ-0001"] == {"code", "rust_test", "behave_test"}
        assert coverage_map["REQ-0002"] == {"code", "behave_test"}

    def test_req_with_no_coverage_is_absent_from_map(self) -> None:
        coverage_map = build_coverage_map(set(), set(), set())

        assert coverage_map == {}


# ---------------------------------------------------------------------------
# find_orphaned_annotations
# ---------------------------------------------------------------------------


class TestFindOrphanedAnnotations:
    def test_returns_empty_set_when_all_annotated_ids_are_defined(self) -> None:
        annotated_ids = {"REQ-0001", "REQ-0002"}
        required_ids = {"REQ-0001", "REQ-0002", "REQ-0003"}

        orphaned = find_orphaned_annotations(annotated_ids, required_ids)

        assert orphaned == set()

    def test_returns_orphaned_ids_not_in_required_set(self) -> None:
        # REQ-9999 was annotated but does not appear in any implemented RFC.
        annotated_ids = {"REQ-0001", "REQ-9999"}
        required_ids = {"REQ-0001"}

        orphaned = find_orphaned_annotations(annotated_ids, required_ids)

        assert orphaned == {"REQ-9999"}

    def test_returns_empty_set_when_annotated_set_is_empty(self) -> None:
        orphaned = find_orphaned_annotations(
            annotated_ids=set(), required_ids={"REQ-0001"}
        )

        assert orphaned == set()


# ---------------------------------------------------------------------------
# find_duplicate_req_ids
# ---------------------------------------------------------------------------


class TestFindDuplicateReqIds:
    def test_returns_empty_dict_when_no_duplicates(self, tmp_path: Path) -> None:
        make_rfc_dir(
            tmp_path,
            "RFC-0001",
            "test",
            [{"clause_id": "C-A", "text": "[REQ-0001] MUST do A."}],
        )
        make_rfc_dir(
            tmp_path,
            "RFC-0002",
            "test",
            [{"clause_id": "C-B", "text": "[REQ-0002] MUST do B."}],
        )
        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        duplicates = find_duplicate_req_ids(implemented_rfcs)

        assert duplicates == {}

    def test_returns_duplicate_with_rfc_ids_when_same_req_in_two_rfcs(
        self, tmp_path: Path
    ) -> None:
        make_rfc_dir(
            tmp_path,
            "RFC-0001",
            "test",
            [{"clause_id": "C-A", "text": "[REQ-0001] MUST do A."}],
        )
        make_rfc_dir(
            tmp_path,
            "RFC-0002",
            "test",
            # REQ-0001 repeated in a second RFC — a governance error.
            [{"clause_id": "C-B", "text": "[REQ-0001] MUST also do B."}],
        )
        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        duplicates = find_duplicate_req_ids(implemented_rfcs)

        assert "REQ-0001" in duplicates
        assert set(duplicates["REQ-0001"]) == {"RFC-0001", "RFC-0002"}

    def test_ignores_req_appearing_in_multiple_clauses_of_same_rfc(
        self, tmp_path: Path
    ) -> None:
        # The same REQ-0001 appears in two clauses of the same RFC; this is
        # not a duplicate — only cross-RFC repetition is reported.
        make_rfc_dir(
            tmp_path,
            "RFC-0001",
            "test",
            [
                {"clause_id": "C-A", "text": "[REQ-0001] MUST do A."},
                {"clause_id": "C-B", "text": "[REQ-0001] Also MUST do A."},
            ],
        )
        implemented_rfcs = load_implemented_rfcs(tmp_path / "gov")

        duplicates = find_duplicate_req_ids(implemented_rfcs)

        assert duplicates == {}


# ---------------------------------------------------------------------------
# End-to-end (run_check with synthetic project layout)
# ---------------------------------------------------------------------------


class TestRunCheck:
    def _build_full_project(self, tmp_path: Path) -> None:
        """Create a minimal synthetic project with one RFC and full coverage."""
        # RFC with two requirements
        clauses = [
            {
                "clause_id": "C-TRANSPORT",
                "text": "[REQ-0001] The agent MUST listen on TLS.\n[REQ-0002] MUST bind port.",
            }
        ]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)

        # Rust source with Implements: and Verifies: annotations
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(
            "/// Implements: REQ-0001, REQ-0002\n"
            "pub fn listen() {}\n\n"
            "        // Verifies: REQ-0001, REQ-0002\n"
            "        assert!(true);\n",
            encoding="utf-8",
        )

        # Feature file with @REQ- tags
        features_dir = tmp_path / "tests" / "system" / "features"
        features_dir.mkdir(parents=True)
        (features_dir / "transport.feature").write_text(
            "  @REQ-0001 @REQ-0002\n  Scenario: TLS connection\n    Given agent is up\n",
            encoding="utf-8",
        )

    def test_passes_when_all_requirements_are_fully_covered(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._build_full_project(tmp_path)

        exit_code = run_check(tmp_path)
        output = capsys.readouterr().out

        assert exit_code == 0
        assert "PASSED" in output

    def test_fails_when_a_requirement_is_missing_coverage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        clauses = [
            {"clause_id": "C-TRAPS", "text": "[REQ-0099] The agent MUST send traps."}
        ]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)
        # No Rust or feature files — no coverage at all

        exit_code = run_check(tmp_path)
        output = capsys.readouterr().out

        assert exit_code == 1
        assert "FAIL REQ-0099" in output
        assert "FAILED" in output

    def test_passes_when_missing_coverage_is_fully_exempted(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        clauses = [
            {
                "clause_id": "C-TRAPS",
                "text": "[REQ-0099] The agent MUST NOT send informs.",
            }
        ]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)
        make_gap_toml(
            tmp_path,
            [
                {
                    "req": "REQ-0099",
                    "missing": ["code", "rust_test", "behave_test"],
                    "rationale": "Enforced by type system.",
                }
            ],
        )

        exit_code = run_check(tmp_path)
        output = capsys.readouterr().out

        assert exit_code == 0
        assert "PASSED" in output

    def test_reports_correct_rfc_and_requirement_counts(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._build_full_project(tmp_path)

        run_check(tmp_path)
        output = capsys.readouterr().out

        assert "1 implemented RFC(s)" in output
        assert "2 requirements" in output

    def test_pre_completion_rfc_requirements_are_not_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # RFCs in spec, impl, or draft phases are not yet complete — their
        # requirements must not be checked.
        clauses = [{"clause_id": "C-FOO", "text": "[REQ-0099] MUST do something."}]
        make_rfc_dir(tmp_path, "RFC-0001", "spec", clauses)
        make_rfc_dir(tmp_path, "RFC-0002", "impl", clauses)
        make_rfc_dir(tmp_path, "RFC-0003", "draft", clauses)

        exit_code = run_check(tmp_path)
        output = capsys.readouterr().out

        assert exit_code == 0
        assert "0 implemented RFC(s)" in output

    def test_strict_mode_fails_on_orphaned_annotation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # RFC defines only REQ-0001, but the Rust file also annotates REQ-9999.
        clauses = [{"clause_id": "C-A", "text": "[REQ-0001] MUST do something."}]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(
            "/// Implements: REQ-0001\n"
            "/// Implements: REQ-9999\n"  # orphaned — not in any RFC
            "// Verifies: REQ-0001\n",
            encoding="utf-8",
        )
        features_dir = tmp_path / "tests" / "system" / "features"
        features_dir.mkdir(parents=True)
        (features_dir / "a.feature").write_text(
            "  @REQ-0001\n  Scenario: A\n    Given something\n",
            encoding="utf-8",
        )

        exit_code = run_check(tmp_path, strict=True)
        output = capsys.readouterr().out

        assert exit_code == 1
        assert "ORPHAN REQ-9999" in output

    def test_strict_mode_passes_when_no_orphaned_annotations(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._build_full_project(tmp_path)

        exit_code = run_check(tmp_path, strict=True)
        output = capsys.readouterr().out

        assert exit_code == 0
        assert "ORPHAN" not in output

    def test_non_strict_mode_ignores_orphaned_annotations(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # REQ-9999 is annotated but undefined; without --strict this must not fail.
        clauses = [{"clause_id": "C-A", "text": "[REQ-0001] MUST do something."}]
        make_rfc_dir(tmp_path, "RFC-0001", "test", clauses)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(
            "/// Implements: REQ-0001\n"
            "/// Implements: REQ-9999\n"
            "// Verifies: REQ-0001\n",
            encoding="utf-8",
        )
        features_dir = tmp_path / "tests" / "system" / "features"
        features_dir.mkdir(parents=True)
        (features_dir / "a.feature").write_text(
            "  @REQ-0001\n  Scenario: A\n    Given something\n",
            encoding="utf-8",
        )

        exit_code = run_check(tmp_path, strict=False)
        output = capsys.readouterr().out

        assert exit_code == 0
        assert "ORPHAN" not in output

    def test_warns_on_duplicate_req_ids_across_rfcs(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # REQ-0001 is claimed by both RFCs — a governance error that must be
        # printed as a WARNING regardless of --strict.
        make_rfc_dir(
            tmp_path,
            "RFC-0001",
            "test",
            [{"clause_id": "C-A", "text": "[REQ-0001] MUST do A."}],
        )
        make_rfc_dir(
            tmp_path,
            "RFC-0002",
            "test",
            [{"clause_id": "C-B", "text": "[REQ-0001] MUST also do A."}],
        )

        run_check(tmp_path)
        output = capsys.readouterr().out

        assert "WARNING REQ-0001" in output
        assert "RFC-0001" in output
        assert "RFC-0002" in output
