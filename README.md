The signed list of mirrors the Phoenix launcher may download releases from.

## Registering your own mirror

Clone this repository and run, on a clean `main`:

    python register_mirror.py https://your-mirror.example

It fetches `<base_url>/register.json` — the entry your host serves about itself — checks it against
`generate_mirror_list.py`'s own rules, writes `mirrors.d/<name>.json`, commits it on a branch and
pushes it with **your** git identity, then prints the compare page (and tries to open it). No token,
no `gh`, no API: git and a browser. It refuses a dirty working tree, a checkout that is not on
`main`, an `origin` that is not on github.com, an entry the generator would reject, and an entry
naming any `base_url` other than the one it was fetched from — a host may register only itself.

A host that already holds a `tokens.registry` credential can open the same pull request itself
(`register.ts` in the mirror repo). This script exists so that running a mirror does not require
one: a token with write access to this repository is write access to what gets signed and
published, and it has no business sitting on a public-facing box.

Either way the result is a pull request a maintainer merges — `main` requires a pull request and an
approving review, so a registration nobody wants is a pull request that gets declined. Merging is
what publishes: the list is rebuilt, sealed with the Phoenix release key and released as the next
serial (`.github/workflows/publish.yml`).
