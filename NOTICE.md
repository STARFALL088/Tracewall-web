# Attribution and third-party terms

## Engine code

`src/main/java/tracewall/net/` and `src/main/java/tracewall/blocklist/` are
copied from [STARFALL088/Tracewall](https://github.com/STARFALL088/Tracewall)
at commit `e5c7c0d`, unchanged apart from a header comment naming that commit.
That repository had no `LICENSE` file when the copy was made, so no licence is
asserted for those files here beyond what the upstream project grants.

## Bundled category lists

These are the exact sources and terms recorded in the upstream Tracewall README
under "Rule data". The files in `lists/` are snapshots; they are not refreshed
by this project.

| File | Entries | Source URL | Licence |
| --- | ---: | --- | --- |
| `lists/malware.txt` | ~420 | [abuse.ch URLhaus](https://urlhaus.abuse.ch/downloads/hostfile/) (existing snapshot) | CC0; existing data, not refreshed by this script |
| `lists/adult.txt` | 60,020 | [Block List Project porn hosts](https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt) | [Unlicense](https://github.com/blocklistproject/Lists/blob/master/LICENSE) |
| `lists/gambling.txt` | 15,020 | [Block List Project gambling hosts](https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt) | [Unlicense](https://github.com/blocklistproject/Lists/blob/master/LICENSE) |
| `lists/ads.txt` | 20,049 | [Block List Project ads hosts](https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt) | [Unlicense](https://github.com/blocklistproject/Lists/blob/master/LICENSE) |

Source URLs and licence links are also embedded in the header of each file.

## Evaluation sample

`eval/domains.tsv` mixes 20 hand-written benign names with 20 positive rows
sampled from the bundled lists above. It inherits their terms.
