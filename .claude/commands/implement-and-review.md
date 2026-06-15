Review and iterate on the implementation of: $ARGUMENTS

This workflow takes precedence and must be followed to the letter.
If you find them ambiguous then STOP and ask.
Do NOT make assumptions or try to be clever.

Follow this loop (max 3 iterations). Skipping steps is STRICTLY PROHIBITED:
1. Use the **implementer** subagent to write the code and tests. **Brief it with the goal and constraints, not step-by-step instructions** — it has access to CLAUDE.md and can read the codebase. Describe *what* to achieve and *why*, not *how* to write it. Do not specify line numbers, exact code snippets, or placement of functions. **Capture its agent ID** — you will resume it in later steps instead of launching a new instance.
2. Use the **reviewer** subagent (opus) to review the result. For new or untracked files, tell the reviewer which files to read. For changes to tracked files, pass the specific `git diff` command to run to get the changes.
3. If the reviewer returns comments, **resume** the implementer (using its agent ID) and pass only the exact reviewer feedback, addressing all MUST FIX, SHOULD FIX, and SUGGESTION items per CLAUDE.md. Do NOT scope-limit based on whether the finding touches code outside the original diff.
4. Stop when there is nothing left that needs fixing, or after 3 iterations.
5. **Before committing:** Run `make pre-commit` and `make behave-test` and fix any failures before recording the commit.

If you encounter a situation where a design decision is unclear or the right approach requires trade-offs between alternatives, ask the user before proceeding.

At the end, summarize what was built and how many iterations it took. Then list all reviewer suggestions that were not fixed — grouped by category (MUST FIX, SHOULD FIX, SUGGESTION) — with the exact suggestion text and the reason it was not addressed (valid reasons: user explicitly declined, or requires a design decision needing user input). If there are no unresolved suggestions, state that explicitly.
