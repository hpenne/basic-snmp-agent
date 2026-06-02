Review and iterate on the implementation of: $ARGUMENTS

This workflow takes precedence over general implementation approach guidelines.

Follow this loop (max 3 iterations):
1. Use the **implementer** subagent to write the code and tests. **Capture its agent ID** — you will resume it in later steps instead of launching a new instance.
2. Run `make test` to verify the build is clean before proceeding (clippy, Rust unit/doc tests, Python tests, Behave tests). If any fail, **resume** the implementer (using its agent ID) and pass only the failures — do not repeat the original task description.
3. Use the **reviewer** subagent (opus) to review the result. For new or untracked files, tell the reviewer which files to read. For changes to tracked files, pass the `git diff` output.
4. If the reviewer returns comments, **resume** the implementer (using its agent ID) and pass only the exact reviewer feedback, addressing all MUST FIX, SHOULD FIX, and SUGGESTION items per CLAUDE.md. Do NOT scope-limit based on whether the finding touches code outside the original diff.
5. Stop when there is nothing left that needs fixing, or after 3 iterations.
6. **Before committing:** Run `make pre-commit` and fix any failures before recording the commit.

If you encounter a situation where a design decision is unclear or the right approach requires trade-offs between alternatives, ask the user before proceeding.

At the end, summarize what was built and how many iterations it took. Then list all reviewer suggestions that were not fixed — grouped by category (MUST FIX, SHOULD FIX, SUGGESTION) — with the exact suggestion text and the reason it was not addressed (valid reasons: user explicitly declined, or requires a design decision needing user input). If there are no unresolved suggestions, state that explicitly.
