Review and iterate on the implementation of: $ARGUMENTS

Follow this loop (max 3 iterations):
1. Use the **implementer** subagent to write the code and tests. **Capture its agent ID** — you will resume it in later steps instead of launching a new instance.
2. Run the following to verify the build is clean before proceeding:
   - `cargo clippy -- -W clippy::pedantic -D warnings` (must produce no warnings or errors)
   - `cargo test --workspace` (all unit and integration tests)
   - `cargo test --doc` (doc tests)
   If any fail, **resume** the implementer (using its agent ID) and pass only the failures — do not repeat the original task description.
3. Use the **reviewer** subagent (opus) to review the result. For new or untracked files, tell the reviewer which files to read. For changes to tracked files, pass the `git diff` output.
4. If the reviewer returns comments, **resume** the implementer (using its agent ID) and pass only the exact reviewer feedback with instruction to **only modify files explicitly flagged in the review** — do not refactor or touch anything else. If a larger refactor seems beneficial, ask for permission first.
5. On re-review, use the **reviewer-followup** subagent (sonnet) and pass the **diff of changed files only**, not the full codebase.
6. Stop when there is nothing left that needs fixing, or after 3 iterations.

If you encounter a situation where a design decision is unclear or the right approach requires trade-offs between alternatives, ask the user before proceeding.

At the end, summarize what was built and how many iterations it took. Then list all reviewer suggestions that were not fixed — grouped by category (MUST FIX, SHOULD FIX, SUGGESTION) — with the exact suggestion text and the reason it was not addressed (e.g. not flagged as must-fix, deferred by user, out of scope). If there are no unresolved suggestions, state that explicitly.
