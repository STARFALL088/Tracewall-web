# MLH submission text

Ready to paste. Keep the pitch under 140 characters; it is 135.

## Project name

Tracewall Desktop

## One-line pitch

> A local DNS filter for your laptop with an optional open-weight model that catches domains no blocklist knows.

## Description

Tracewall Desktop is a standalone UDP DNS sinkhole in Java 17 with no
third-party dependencies. Point any device's DNS at it and every lookup is
checked against four bundled hosts-format lists - malware, gambling, adult and
ads, about 95,000 merged rules that load in under a second - before being
forwarded to the upstream resolvers you choose. Blocked A queries answer
`0.0.0.0`; every other blocked type gets an empty NOERROR answer, so clients do
not fall back to the real address over another record type.

The filtering engine is not new: it is the pure-JVM core of Tracewall, an
Android `VpnService` app written earlier for a university course, copied
unchanged and credited at the top of every file. What is new is everything
around it: the UDP server with a bounded worker pool, per-client CIDR
restriction, the AI classifier, an accuracy evaluation harness, and a live
loopback dashboard with persistent allow/block overrides.

The AI layer is the interesting part. When no list has an opinion on a domain,
`AiClassifier` sends only the validated registrable hostname to an open-weight
model served locally by Ollama and asks for a category and a confidence score
as JSON. It blocks only `adult`, `gambling` or `malware` at or above a
configurable threshold, defaults to 0.8. Everything else falls through to the
normal rules. A slow, offline or malformed model answer is treated as "no
opinion" and the query is allowed, so filtering never breaks name resolution.
Failures are remembered for 60 seconds and retried, never written to the
verdict cache. Successful verdicts are cached in a TSV file, so a demo repeats
offline.

The dashboard is one embedded HTML page with no build step and no external
scripts: live query feed, counters, top blocked domains, the AI verdict table
with Mark safe and Block buttons, and a manual override form. Overrides are
written into the engine's allow list and custom deny list, not around it, and
they persist to `overrides.tsv`. Writes need a random per-run token and a
loopback Origin and Host.

33 JUnit 5 tests run with no network: classifier validation and caching, failure
expiry, malformed model output, blocked A and AAAA answers, allowlist
precedence, garbage-packet survival, client allowlists, and the dashboard's
JSON endpoints and token checks. Model behaviour is tested against an
in-process fake Ollama. The classifier has not yet been run against real
inference; the repo ships an evaluation harness and a 40-row labelled sample
for that, with a header that says plainly the positives come from the same
blocklists, so it is a sanity check and not a benchmark.

## Technologies

Java 17, Gradle 8.9 with a pinned toolchain, UDP DNS, `java.net.http`,
`com.sun.net.httpserver`, JUnit 5, Ollama.

## AI your project calls

- **Ollama** - yes, at runtime, over loopback HTTP (`POST /api/generate`).
- **Model family** - `<fill in the family of the model you actually run>`.
  The code has no default tag on purpose; it is set with `--ai-model` or
  `TRACEWALL_AI_MODEL`.

No cloud AI API is called by the shipped code. There is no OpenAI, Anthropic,
Gemini or other provider client in the repository.

## Links

- Repository: `<your public GitHub URL>`
- Demo video: `<add after recording>`
- Evaluation notes: `eval/domains.tsv` and the Testing section of the README.

## Suggested prize category

**Best Open-Source AI Project** - the classifier is an important, load-bearing
part of the filter rather than a bolt-on: it is the only mechanism that can
block a domain no list has seen, it runs entirely on an open-weight model the
user chooses, and the whole pipeline from prompt to override is in the
repository under MIT.
