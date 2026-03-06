Review and iterate on the implementation of: $ARGUMENTS

Follow this loop (max 3 iterations):
1. Use the **implementer** subagent to write the code and tests
2. Use the **reviewer** subagent to review the result
3. If the reviewer returns comments, pass the **exact reviewer feedback verbatim** to the implementer with instruction to **only modify files explicitly flagged in the review** — do not refactor or touch anything else
4. On re-review, pass the **diff of changed files only** to the reviewer, not the full codebase
5. Stop when there is nothing left that needs fixing, or after 3 iterations

At the end, summarize what was built, how many iterations it took, and any unresolved suggestions.