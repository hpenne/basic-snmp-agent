Apply an approved CodeScene suppression directive for: $ARGUMENTS

$ARGUMENTS identifies the finding to suppress — ideally a "suppress:" line copied from a
`/codescene-improve` log, otherwise: the file, the exact smell name (verbatim from `code_health_review`),
and the function it applies to.

This is the deliberate, human-invoked counterpart to `/codescene-improve`, which only *recommends*
suppressions. Suppression is permanent and makes CodeScene stop reporting the finding, so it is treated as a
real code change: route it through existing infrastructure, no exemptions.

This workflow takes precedence and must be followed to the letter. If anything is ambiguous, STOP and ask.

## Rules

- **Verify scope first.** `@codescene` directives suppress FUNCTION-level smells only and ALWAYS apply to the
  function/method immediately following the comment. If the finding is module/file-level (e.g. an aggregate
  "X% of functions have primitive args", Low Cohesion, Lines of Code, Brain Class, Developer Congestion),
  STOP: it cannot be inline-suppressed — tell the user it requires `.codescene/code-health-rules.json` and do
  not edit the source.
- **Exact name match.** The disable string MUST be the smell name exactly as it appears in
  `code_health_review`. If you do not have the verbatim name, run `code_health_review` on the file to get it.
- **Always include rationale + date** alongside the directive (CodeScene best practice; keeps the suppression
  auditable). Get the date via `date`.

## Procedure

1. Resolve the file, the verbatim smell name, and the target function. Confirm the smell is currently reported
   by `code_health_review` for that function (do not suppress a finding that is not present). Confirm it is
   function-level per the rules above.
2. Apply the directive via `/implement-and-review`: place `// @codescene(disable:"<exact smell name>")`
   (combine multiple rules as `disable:"A", disable:"B"`, or use `disable-all` only if the user asked to
   suppress everything for that function) on the line(s) immediately above the function, accompanied by a
   short human-readable rationale comment and the date. The reviewer must confirm: correct placement (directly
   above the right function), exact-name match, and that no surrounding code changed.
3. Re-run `code_health_review` on the file and confirm the targeted finding is now absent (and that no other
   finding changed). This is verification of the suppression, not a quality gate.
4. Commit (project git rules: branch if on the default branch; NO mention of Claude/Anthropic). The commit
   message must state which smell was suppressed, on which function, and the rationale.

## Summary

Report the directive added, the function and file, the rationale, and confirmation that `code_health_review`
no longer reports the finding. If the finding was module/file-level and therefore not suppressed, say so and
point to the `.codescene/code-health-rules.json` route.
