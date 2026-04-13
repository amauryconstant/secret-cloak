# vibeguard

OpenCode plugin that redacts secrets/PII via gitleaks before LLM requests and restores them locally after.

## Stack

- Runtime: Bun 1.3
- Language: TypeScript (ES2022, strict mode)
- Build: tsdown
- Linting: oxlint + oxfmt
- Testing: bun test

## Commands

```bash
bun test              # Run tests
bun run build         # Build to dist/
bun run lint          # Lint with oxlint
bun run format        # Format with oxfmt
```

## Architecture

```
src/
├── index.ts     # Plugin entry point
├── detector.ts  # Secret/PII detection via gitleaks
├── engine.ts    # Core redaction/restoration logic
├── session.ts   # Session state management
├── config.ts    # Configuration loading/validation
├── deep.ts      # Deep operation utilities
└── types.ts     # Shared TypeScript types
```

## Patterns

- Plugin hooks into OpenCode message pipeline via `@opencode-ai/plugin`
- Session-based state: each request has unique ID for tracking redactions
- Detector returns match locations; engine handles substitution
- Config uses schema validation with fallback defaults

## Skills

For OpenCode plugin development: `.opencode/skills/create-opencode-plugins/`
For Bun usage: `.opencode/skills/bun-usage/`
