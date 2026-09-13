# Diagrams

Architecture diagrams for `audit-me`, rendered at 2x for README and slide use.
Light and dark variants of each.

| File | Shows |
|---|---|
| `01-pipeline` | The five stages, and the boundary between what runs on the request path and what doesn't |
| `02-asgi-capture` | How the body is captured without consuming it — the wrapped `receive`/`send` |
| `03-redaction` | Header allowlist vs body denylist, and the four caps |
| `04-queue-file` | The byte-bounded queue and the single background writer |
| `05-outage` | What an Elasticsearch outage looks like — measured, not modelled |
| `06-mapping` | 51 fields vs 20,194, against the 200-field limit |

Source: the SVGs live in the architecture page these were rendered from. To
regenerate, screenshot each `<figure>`'s SVG with headless Chrome at
`--force-device-scale-factor=2` and crop to content.
