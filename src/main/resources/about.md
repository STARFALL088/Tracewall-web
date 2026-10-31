## What Tracewall Desktop is
Tracewall Desktop is a local DNS sinkhole for a laptop or home network. Point any device's DNS at it and it blocks malware, gambling, adult and ad domains using four bundled lists, and shows every decision live in this dashboard. When a domain matches no list it can ask a local open-weight model served by Ollama for a second opinion. It fails open, so a missing model never breaks name resolution.

## How a query is decided
Decision order: an explicit allow beats a custom deny, a custom deny beats a category list, and a category list beats the default allow. Only when the result is the default allow is the AI model consulted, and its verdict can only block, never allow. Allowed names are forwarded to the upstream resolvers, 1.1.1.1 and 8.8.8.8 by default.

## What a blocked domain returns
A blocked A query gets the address 0.0.0.0. Other record types, such as AAAA, get an empty NOERROR answer with no records. The question section is echoed back.

## Dashboard overview
This page refreshes every second. The stat cards at the top summarise traffic; see the stat card meanings section. Top blocked domains is counted from the most recent events. AI verdicts lists what the model said about unknown names. Live queries shows the latest 200 decisions with time, action, host, reason and client. The dashboard listens on loopback only.

## Stat card meanings
Queries is every DNS query received. Blocked is list blocks plus custom blocks plus AI blocks. By list means a category list matched. By AI means the model blocked a name no list knew. Allowed means the query was forwarded. Servfail means the upstream resolver failed or timed out. Dropped means the query was refused or discarded, for example from a client outside the allowed client ranges or when the worker pool was full. AI calls counts requests actually sent to the model; repeated domains are answered from the cache.

## Overrides
Use the Override a domain box, or the buttons in the AI verdicts table. Mark safe adds an allow, which beats every list. Block adds a custom deny, which still loses to an explicit allow. Both persist to overrides.tsv. Overrides need the write token embedded in this page, so they only work from the dashboard itself.

## AI classifier
The classifier is optional and off unless a model is named with --ai-model or TRACEWALL_AI_MODEL. It only asks about names no list matches, sends only the validated registrable domain, and blocks only adult, gambling and malware at or above a confidence threshold, 0.8 by default. Verdicts are cached in ai-cache.tsv, failures are retried after 60 seconds, and a query waits 1500 ms for the model by default before being allowed. A roughly 1 to 4 billion parameter instruction model is recommended on a machine without a GPU.

## Running it
Run ./gradlew run --args="--lists lists --allow example.com". The DNS server listens on UDP port 5354 by default and the dashboard is at 127.0.0.1 on port 8080. Useful flags: --port, --bind, --allow, --allow-client, --upstream, --stats-interval and --dashboard-port. Test with dig @127.0.0.1 -p 5354 xvideos.com, which should return 0.0.0.0.

## Protecting a phone
The phone must reach UDP port 53 on the laptop. Free port 53 (systemd-resolved owns it by default), run the fat jar as root with --port 53 --bind 0.0.0.0 and --allow-client for your LAN, set the phone's Wi-Fi DNS to the laptop's LAN address, and allow UDP 53 in the firewall. Binding to 0.0.0.0 makes an open resolver, so always restrict it with --allow-client. This setup has not been verified on a real phone.

## Privacy
Queries and domain names never leave the machine except to the upstream resolvers you configure, so your browsing data stays private. The model runs through Ollama: a local model keeps everything on the machine, while a cloud tag such as gemma4:31b-cloud sends the question and the matching docs sections to ollama.com. Recently blocked hostnames are withheld from cloud models, so browsing history is never sent that way. The dashboard listens on loopback only, and ai-cache.tsv and overrides.tsv are local files. Pointing --ai-url at a remote Ollama instance ends the local-model guarantee. This chat assistant runs through the same model, or answers from built-in docs when no model is configured.

## Limits
The classifier sees only the hostname, not the page, so it will be wrong sometimes. It fails open by design. DoH and Private DNS bypass the filter, as do direct IP connections and cached addresses. There is no per-device policy. DNS cannot block individual paths or channels, only whole hosts. The lists are incomplete. It is UDP only with IPv4 upstreams, has no DNS-over-TLS upstream, and does not validate DNSSEC.

## Origin and licence
The filtering engine was written earlier for a university Android course in the Tracewall VpnService app, and this repository is the standalone desktop build. The UDP server, query handler, Ollama client, evaluation harness, dashboard and tests are new. It is MIT licensed; the bundled lists have their own terms, described in NOTICE.md.
