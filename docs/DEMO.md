# Three-minute demo script

Two terminals, one browser tab. The timings assume the model is already pulled
and the cache is prewarmed.

## Before you record

```bash
./gradlew test                                   # 33 tests, takes seconds
ollama list                                      # note the tag you will use
```

Open a browser tab at <http://127.0.0.1:8080> but do not start the server yet.

## Terminal A - start the filter

```bash
./gradlew run --args="--lists lists --allow example.com \
  --ai-model <tag> --ai-prewarm examples/demo-domains.txt"
```

Say: this loads four lists, about 95,000 rules, in under a second, and then
classifies a handful of demo names so the model is warm before the first query.
Point at the printed lines: `loaded 4 categories / 95515 rules`, the
`AI classifier:` line, and the dashboard URL with its write token.

## Terminal B - the three behaviours (about 90 seconds)

```bash
dig @127.0.0.1 -p 5354 xvideos.com +short
```

Expect `0.0.0.0`. Say: this name is on the adult list, so the engine answers
with the null address and the app never connects.

```bash
dig @127.0.0.1 -p 5354 xvideos.com AAAA +short
```

Expect no output. Say: for AAAA the filter returns an empty NOERROR instead of
a fake address, so the client does not fall back to the real IPv6 address.

```bash
dig @127.0.0.1 -p 5354 example.com +short
```

Expect real addresses. Say: `example.com` is allowlisted, and an explicit allow
beats every category in the engine.

```bash
dig @127.0.0.1 -p 5354 casino-bonus-guide.xyz +short
```

Expect `0.0.0.0`. Say: no list knows this name. It was classified by the local
model as gambling with high confidence, so it is blocked. This is the part the
lists cannot do.

## Browser - overrides and live feed (about 45 seconds)

1. Show the counters at the top: queries, blocked, blocked by AI.
2. Scroll to **AI verdicts**, find `casino-bonus-guide.xyz`, point at its
   category and confidence.
3. Click **Mark safe**. Back in Terminal B, repeat the `dig`. It now resolves.
   Say: the override is written into the engine's allow list, not around it, and
   it is persisted to `overrides.tsv`.
4. Click **Block** on the same row. The `dig` is blocked again.
5. Scroll to **Live queries**. Every decision is there with its reason.
6. Wait for the 10-second stats line in Terminal A and read it out.

## Closing line

Say: it is a desktop build of a filtering engine written for an Android course,
plus a desktop server, an optional local open-weight classifier, an evaluation
harness and this dashboard. It fails open, it only sees hostnames, and the
README says exactly where that is not enough.

## Fallback - no model available

If Ollama is not running, do not improvise. Drop the AI flags:

```bash
./gradlew run --args="--lists lists --allow example.com"
```

Then:

1. `dig xvideos.com` returns `0.0.0.0`, `dig xvideos.com AAAA` is empty,
   `dig example.com` resolves. Same three behaviours, list-driven.
2. In the dashboard, type `example.com` into **Override a domain** and click
   **Block**. `dig @127.0.0.1 -p 5354 example.com` now returns `0.0.0.0`.
   Type it again and click **Mark safe**; it resolves. Say: overrides work with
   the model off because they go through the same policy engine, and the
   allow/deny precedence is the engine's own.
3. Say plainly: the AI layer is off in this run; it is covered by tests against
   a fake Ollama, and the evaluation harness is in the repo but has not been run
   against a real model yet.

Do not claim a model verdict in the fallback run.
