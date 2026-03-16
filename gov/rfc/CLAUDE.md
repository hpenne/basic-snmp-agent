# RFC Authoring Rules

## Requirement Tags

Every sentence in a normative RFC clause that contains a requirement keyword
(MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY) must begin with a
unique requirement tag of the form `[REQ-XXXX]`, where `XXXX` is a zero-padded
four-digit decimal number (e.g. `[REQ-0042]`).

Rules:

- Tags must be globally unique across all RFCs and clauses.
- Each tagged sentence must start with its tag as the very first token, before
  any other text.
- When adding a new requirement, assign the next sequential number after the
  highest existing tag.
- Tags must never be reused, even if a requirement is removed or a clause is
  deleted.
- Tags must never be renumbered or reassigned.
- Informative sentences (rationale paragraphs, scope notes, non-normative
  descriptions) must not carry tags.
