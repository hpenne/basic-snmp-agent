Run cargo-mutants this crate: $ARGUMENTS

Follow this loop (max 3 iterations):
1. Run cargo-mutants on $ARGUMENTS, using a 5 second timeout
2. Use the **implementer** agent to add tests for uncaught mutants. If a mutant seems impossible to catch or some other fix than a new test seems reasonable, ask me before proceeding.
3. Run cargo test on $ARGUMENTS to verify that nothing is broken.
4. Pass the changes to the **reviewer** agent for review
5. If the reviewer returns comments, pass the **exact reviewer feedback verbatim** to the implementer with instruction to **only modify files explicitly flagged in the review** — do not refactor or touch anything else
6. On re-review, pass the **diff of changed files only** to the reviewer, not the full codebase
7. Stop when there is nothing left that needs fixing, or after 3 iterations

At the end, summarize what was built, how many iterations it took, and any unresolved suggestions.