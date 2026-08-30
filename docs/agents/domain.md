# Domain Docs

How engineering skills consume this repository's domain documentation.

## Before Exploring

- Read `CONTEXT.md` at the repository root.
- Read ADRs under `docs/adr/` that affect the area being changed.
- If either source does not exist, proceed without raising its absence.

## Layout

This is a single-context repository:

```
/
├── CONTEXT.md
└── docs/adr/
```

## Vocabulary And Decisions

Use the glossary terms defined in `CONTEXT.md` in issues, specifications, test names, and design discussions. Surface any conflict with a relevant ADR rather than silently overriding it.
