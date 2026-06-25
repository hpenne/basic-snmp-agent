Run CodeScene-guided code-quality improvement on: $ARGUMENTS

$ARGUMENTS is one or more target files (and optional flags). Recognised flags:
`autonomous` (default is supervised), `threshold=<high|medium|marginal>` (default `medium`
— stop when only items below this band remain), `budget=<N>` (max fixes this run, default 8).

This workflow takes precedence and must be followed to the letter. If anything is ambiguous, STOP and ask.
Do NOT make assumptions or try to be clever. Use ONLY existing infrastructure (the `/implement-and-review`
command, the **implementer**/**reviewer** subagents, the project's real `make`/`cargo` commands, the
CodeScene MCP tools, govctl and CLAUDE.md rules) — no bespoke harness, no special exemptions.

## Two load-bearing rules (these are why this command exists)

- **RULE A — the CodeScene score is a MEASUREMENT, never the success or stop signal.** Empirically, genuine
  improvements often move the score by 0.00 (the metric is category/tier-driven, not proportional), and the
  single most score-moving change is frequently the most *harmful* one. The success gate for any fix is:
  reviewer-confirmed quality/readability improvement + green tests + clean clippy + NO new smell introduced.
  Never keep/discard a fix, and never rank work, on score delta.
- **RULE B — steelman before you dismiss.** A finding may be classified "won't-do" (false positive, or a fix
  that would not improve readability) ONLY after you have: (1) considered at least two distinct refactoring
  methods, not just the obvious one; (2) asked what wider design gap the finding might point at (e.g.
  "Primitive Obsession → is there a missing domain type?"); and (3) tested each reason-to-dismiss against
  standard techniques (`From`/`.into()`, an extracted helper, a newtype, a different boundary). Write the
  steelman into the log. Premature dismissal is the primary failure mode this command guards against.

## Procedure

0. **Setup.** Resolve target files, mode, threshold, budget. Run `date` for a timestamp. Create the decision
   log at `<repo>/.codescene/runs/<timestamp>-<branch>.md` (create the directory if needed) and write the
   run header (date, branch, target files, mode, threshold, budget).

1. **Baseline.** For each target file run `code_health_review` and `code_health_score`; record both in the log.
   Keep the verbatim smell-category names from the review — you will need exact strings later.

2. **Classify every finding (RULE B applies to each).** Bucket each into exactly one of:
   - **actionable** (true positive worth fixing) — score it on the value rubric below;
   - **won't-do** (false positive, or fix would not improve readability) — record rationale + a confidence
     0.0–1.0 that the dismissal is correct;
   - **marginal** (real but low value) — record why.
   Then enforce the adversarial check on every won't-do:
   - **Supervised mode:** present all won't-do classifications with their rationales and invite the user to
     push back BEFORE proceeding. Wait for the user.
   - **Autonomous mode:** for each won't-do, launch a fresh devil's-advocate subagent **on the opus model**
     (the same strong model as the **reviewer** — do NOT use the weaker implementer model for this
     critical-reasoning task) tasked ONLY to argue the finding IS worth fixing and propose the non-obvious
     method. A dismissal is final only if it survives that challenge; if the challenge is convincing, move the
     finding to actionable. Do NOT stop to ask the user — autonomy means keep going. When you hit a genuine
     trade-off (e.g. a fix that helps the metric but harms readability/traceability), do NOT action it and do
     NOT halt: record it PROMINENTLY in the log as a flagged item the user should investigate further, and
     carry on. The log is the asynchronous pushback channel that replaces the interactive stop.

   **Value rubric** (apply consistently): score Quality gain (clarity/safety/maintainability), Confidence it
   is a true positive (post-steelman), and Risk/blast-radius (inverted), each Low/Med/High → composite band
   **High / Medium / Marginal**. Rank by GENUINE quality value, explicitly NOT by predicted score movement.

3. **Rank** the actionable set by value band. Exclude won't-do, marginal-below-threshold, and anything
   CodeScene no longer reports (suppressed). If the set is empty, or its top item is below `threshold`, go to 7.

4. **Execute the top item** via `/implement-and-review`, briefing it with the goal and constraints (not
   step-by-step). One finding per invocation.

5. **Verify (RULE A — score is not the gate).** Do NOT re-run the unit tests/clippy here — `/implement-and-review`
   already ran them inside its own loop; trust that. Instead, re-run `code_health_review` on the file to confirm
   NO new smell was introduced. The fix PASSES only if implement-and-review's reviewer confirmed quality AND no
   new smell appeared. Record the before/after score as a measurement only. If a new smell appeared, or
   implement-and-review could not reach a clean state within its 3-iteration limit, REVERT the change
   (`git restore`/`git checkout`) and mark the item **failed**; move it to won't-do with the reason and continue.

6. **Commit.** Run `make pre-commit` (the project's full gate: tests + python-lint + fuzz + traceability +
   format check) — outside the command sandbox, or its bind tests fail. Commit only if it passes; if it fails,
   fix via `/implement-and-review` or REVERT and mark the item failed. Then commit (project git rules: branch if
   on the default branch; NO mention of Claude/Anthropic, no Co-Authored-By trailers). Log the iteration (see
   format). Return to 3.

7. **Stop** when: the actionable set is empty, OR the top-ranked remaining item is below `threshold`, OR the
   `budget` fix cap is reached, OR per-fix discards are exhausted. Never stop on "score plateaued".

## Suppression — recommend, NEVER apply

This command must NOT write `@codescene` directives. For each function-level false positive, emit a
**paste-ready recommendation** in the log: the exact directive `// @codescene(disable:"<verbatim smell
name>")` placed immediately above the named function, plus a one-line rationale and the date. Use the smell
name EXACTLY as it appears in `code_health_review` (CodeScene requires an exact match). For module/file-level
findings (e.g. an aggregate "X% of functions have primitive args", Low Cohesion, Lines of Code, Brain Class)
note that inline suppression is NOT possible and that suppression requires `.codescene/code-health-rules.json`
instead. Applying an approved suppression is the separate `/codescene-suppress` command, run by a human.

## Decision log format (fit for post-run scanning + feeding suppressions)

The log's primary reader is a human scanning for skips that deserve pushback. Order and content accordingly:

```
# CodeScene run — <date> · <branch>
Targets: <files> · Mode: <supervised|autonomous> · Threshold: <band> · Budget: <N>
Score: <file>: <before> → <after>   (measurement only — not a success signal)
Totals: actionable <a> · fixed <f> · won't-do <w> · marginal <m> · failed <x>

## ⚠ Skipped — review for pushback        (ascending dismissal-confidence: shakiest first)
- [conf 0.40] <file> · <smell> · <scope: function NAME | module> · band <…>
    why skipped: <one line>
    steelman: methods considered=[…]; wider-picture=<…>; why each fails=<…>
    suppress: <paste-ready // @codescene(disable:"<smell>") + rationale + date>   (function-level only;
              else: "not inline-suppressible — use .codescene/code-health-rules.json")
- [conf 0.90] …

## ↘ Skipped — below value threshold (marginal)
- <file> · <smell> · <scope> — <why marginal>   (re-runnable with a lower threshold)

## ✅ Fixed
- <file> · <smell> · <scope> — commit <hash>
    what: <one line> · rationale: <…> · tests: green · clippy: clean · score Δ: <before→after> (measurement)

## ✗ Failed / reverted
- <file> · <smell> — <reason> (reverted)
```

## End-of-run summary

Report: score before/after per file (as a measurement, with the explicit note that it may be unchanged for
genuine improvements); commits made; and — most important — the count and the top few **low-confidence
skips** the user should review for pushback, pointing at the log path. List any items requiring a user
trade-off decision that were deferred. State the stop condition that fired.
