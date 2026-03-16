Run cargo-mutants this crate: $ARGUMENTS

Follow this loop (max 3 iterations):
1. Run cargo-mutants on $ARGUMENTS, using a 5 second timeout
2. Use the **implementer** agent to add tests for uncaught mutants. If a mutant seems impossible to catch (e.g. is in redundant logic) or some other fix than a new test seems reasonable, ask before proceeding. **Capture the implementer's agent ID** — you will resume it in later steps.
3. Run cargo test on $ARGUMENTS to verify that nothing is broken.
4. Re-run cargo-mutants on $ARGUMENTS to confirm the previously missed mutants are now caught. If any remain missed, **resume** the implementer (using its agent ID) and pass only the remaining uncaught mutants — do not repeat the original task. Return to step 3.
5. Pass the changes to the **reviewer-followup** agent (sonnet) for review. For new or untracked files, tell the reviewer which files to read. For changes to tracked files, pass the `git diff` output.
6. If the reviewer returns comments, **resume** the implementer (using its agent ID) and pass only the exact reviewer feedback with instruction to **only modify files explicitly flagged in the review** — do not refactor or touch anything else.
7. On re-review, pass the **diff of changed files only** to the reviewer-followup, not the full codebase.
8. Stop when there is nothing left that needs fixing, or after 3 iterations.

At the end, summarize what was built, how many iterations it took, and any unresolved suggestions.
