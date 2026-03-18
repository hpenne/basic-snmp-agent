Review all uncommitted changes in the working tree.

Follow this loop (max 3 iterations):
1. Run the following to verify the build is clean before reviewing:
   - `cargo clippy -- -W clippy::pedantic -D warnings` (must produce no warnings or errors)
   - `cargo test --workspace` (all unit and integration tests)
   - `cargo test --doc` (doc tests)
   If any of these fail, use the **implementer** subagent to fix them (passing the failures and `git diff HEAD` as context), **capture its agent ID**, then re-run all checks. If checks still fail after the implementer's fix, report the remaining failures to the user and stop.
2. Use the **reviewer** subagent (opus) to review the result. Pass the full `git diff HEAD` output as context.
3. If the reviewer returns comments:
   - If the implementer was already used in step 1, **resume** it (using its agent ID) and pass only the exact reviewer feedback.
   - Otherwise, launch a fresh **implementer** subagent with `git diff HEAD` and the review feedback as context, and **capture its agent ID**.
   In both cases, instruct the implementer to **only modify files explicitly flagged in the review** — do not refactor or touch anything else. If a larger refactor seems beneficial, ask for permission first.
4. After the implementer addresses feedback, re-run all checks from step 1. If they pass, use the **reviewer-followup** subagent (sonnet) and pass the **diff of changed files only**, not the full codebase.
5. Stop when there is nothing left that needs fixing, or after 3 iterations.

If you encounter a situation where a design decision is unclear or the right approach requires trade-offs between alternatives, ask the user before proceeding.

At the end, summarize the review outcome and how many iterations it took. Then list all reviewer suggestions that were not fixed — grouped by category (MUST FIX, SHOULD FIX, SUGGESTION) — with the exact suggestion text and the reason it was not addressed (e.g. not flagged as must-fix, deferred by user, out of scope). If there are no unresolved suggestions, state that explicitly.
