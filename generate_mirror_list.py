#!/usr/bin/env python3
"""Build `mirrors.json` — the signed list of hosts a launcher may download releases from.

    python generate_mirror_list.py build --serial 7 --out mirrors.json
    python generate_mirror_list.py selftest

WHY IT IS SIGNED. The launcher PERSISTS this list: a published list replaces the mirror set
wholesale, so one hostile answer does not mislead a single download, it permanently rewrites where
that client fetches every future release from. The signature is the same Ed25519 release key every
payload is sealed with (release-tooling's tools/seal.py), which is why this repo builds the document
and never signs it itself — sealing is one shared command, not a fourth private copy of one.

WHY IT IS NOT A MANIFEST. A mirror list has no files and no bundles, and release-tooling's
build_manifest derives its `schema` from whether bundles are present; pushing an empty document
through it would mean special-casing emptiness in the one assembler that must never learn a special
case. So this is its own small format — `format: 1`, `payload_id: "mirrors"` — and this file is the
whole of it. Nothing here imports manifest_schema or build_manifest, and "mirrors" is deliberately
not in their PAYLOAD_IDS.

WHY ONE FILE PER MIRROR. `mirrors.d/<name>.json` holds exactly the object that lands in the output
array. A registration is then one added file: a reviewer reads the whole change at once, and two
registrations in flight cannot silently merge into a broken list — they either touch different paths
or git refuses them as the conflict they are. The filename is the mirror's `name`, checked against
the field rather than derived from it, so a renamed file and a stale field can never disagree
quietly.

EVERY CHECK BELOW REFUSES rather than repairs, and refuses with the offending file named. The
failure this exists to prevent is not a malformed document — it is a WELL-FORMED one that silently
ships nothing: a mirror whose URL never resolves because of a trailing slash, a registration saved
as `.jsn`, a `payload` key that is ignored because the field is `payloads`. None of those produce an
error anywhere downstream; the client simply never uses the mirror, and the publisher sees a green
build. This is the only place they can be caught.

Stdlib only, deliberately: validation must run on a pull request from a fork with no install step
and nothing to compromise. The signing dependency (`cryptography`) belongs to seal.py, on main.
"""
import argparse
import json
import os
import re
import sys
from typing import NoReturn

# --- the format ---------------------------------------------------------------------------------

# This document's own version, independent of the manifest format's `schema`. Nothing derives it:
# there is exactly one shape a mirror list can have.
FORMAT = 1

# The payload line this document belongs to. The launcher ratchets a serial PER payload_id, so this
# string is what keeps a mirror list's numbering from being compared against the mod's.
PAYLOAD_ID = "mirrors"

# Which payload trees a mirror may claim to serve. Emitted in THIS order, never the input's, so the
# output does not record how a registration happened to be typed.
PAYLOADS = ("mod", "launcher", "game")

# Exactly the keys an entry carries -- no more (an unknown key is a typo that would be dropped in
# silence) and no fewer.
ENTRY_KEYS = ("base_url", "name", "country", "payloads")

# Every number in this family of formats is a u64 on the wire and a reader parses it into one, so a
# value above this renders a document no reader can parse back. Same ceiling, same reason, as
# release-tooling's manifest_schema.U64_MAX -- stated rather than imported, because importing it
# would be this repo's only dependency on that module and it exists to have none.
U64_MAX = (1 << 64) - 1

# Lowercase only. `name` is an identity compared across files AND is a filename, and the two
# filesystems this repo is edited on disagree about case: `phx-fi-1.json` and `PHX-FI-1.json` are
# one file on a Windows dev box and two in CI, which would make "names are unique" mean two
# different things depending on where it was checked.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Shape only, never a table of the world's countries. `country` is a label the settings pane shows
# next to a host; an ISO 3166 list checked in here would be a copy of a moving external fact that
# nothing in this repo can keep current, and its only power would be to refuse a legitimate mirror.
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

# `signed_at` is ADVISORY -- no reader may fail on it, and nothing here computes it (see build()).
# This checks only that a value handed in looks like the instant it claims to be, which is producer
# hygiene: a garbled timestamp is quotable in a signed document forever.
SIGNED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class MirrorListError(Exception):
    """A registration this list refuses to publish. Every one of these is a release that must not
    happen rather than a warning to read later, so nothing catches these except the CLI."""


# --- the URL rule -------------------------------------------------------------------------------

def launcher_canonical(url):
    """The launcher's own canonical form of a mirror base URL, or None if it is not one.

    A transcription of `config::normalize_mirror_url` in the launcher's src-tauri/src/config.rs --
    the client's rules are the authority on what a mirror URL is, and this exists ONLY to ask
    whether a published string is already the form the client would derive. Nothing here normalizes
    anything: a URL that is not already canonical is refused, because the string in a signed
    document is what a reviewer reads and what every future reader receives.
    """
    u = url.strip().rstrip("/")
    for scheme in ("https://", "http://"):
        if u.startswith(scheme):
            return u if len(u) > len(scheme) else None
    return None


def check_base_url(url):
    if not isinstance(url, str):
        raise MirrorListError(f"base_url must be a string, not {type(url).__name__}")
    if not url.isascii() or any(c.isspace() or ord(c) < 0x20 for c in url):
        raise MirrorListError(
            f"base_url must be plain ASCII with no whitespace: {url!r}\n"
            "  Everything downstream appends a path to this string and hands it to an HTTP client; "
            "an internationalised host has to be punycoded before it is published, not after.")
    # HTTPS only. This is STRICTER than the launcher, which accepts http:// as well -- it is a
    # publishing decision, not a client limit: a plaintext mirror lets any middlebox on the path
    # choose which release a client sees. The signature would still catch a tampered payload, so
    # the attack this closes is the denial one -- and on the networks mirrors exist for, that is
    # the likely one.
    if not url.startswith("https://"):
        raise MirrorListError(f"base_url must start with https:// : {url!r}")
    # The FIXED POINT test. Anything the launcher would strip -- surrounding whitespace, a trailing
    # slash -- must already be gone, or the published string and the string the client actually uses
    # are two different things.
    canonical = launcher_canonical(url)
    if canonical is None:
        raise MirrorListError(f"base_url is empty after its scheme: {url!r}")
    if canonical != url:
        raise MirrorListError(
            f"base_url is not in canonical form: {url!r}\n"
            "  The launcher trims whitespace and trailing slashes before use "
            f"(config::normalize_mirror_url), so publish the trimmed form: {canonical!r}")


# --- entries ------------------------------------------------------------------------------------

def check_entry(entry, stem=None):
    """One mirror, in isolation. `stem` is the filename it was loaded from, when it came from one."""
    if not isinstance(entry, dict):
        raise MirrorListError(f"a mirror must be a JSON object, not {type(entry).__name__}")
    missing = [k for k in ENTRY_KEYS if k not in entry]
    if missing:
        raise MirrorListError("missing " + ", ".join(missing))
    unknown = [k for k in entry if k not in ENTRY_KEYS]
    if unknown:
        raise MirrorListError(
            "unknown key(s) " + ", ".join(repr(k) for k in sorted(unknown)) +
            f"; a mirror carries exactly {', '.join(ENTRY_KEYS)}\n"
            "  A key nothing reads is a setting that looks applied and is not.")

    name = entry["name"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise MirrorListError(
            f"name must match {NAME_RE.pattern} (lowercase; it is also the filename): {name!r}")
    if stem is not None and name != stem:
        raise MirrorListError(
            f"name {name!r} does not match the filename {stem!r}\n"
            "  The file is named for the mirror so a registration is legible as a path; rename one "
            "of the two rather than letting them drift.")

    check_base_url(entry["base_url"])

    country = entry["country"]
    if not isinstance(country, str) or not COUNTRY_RE.match(country):
        raise MirrorListError(
            f"country must be a two-letter uppercase code, e.g. 'FI': {country!r}")

    payloads = entry["payloads"]
    if not isinstance(payloads, list) or not payloads:
        raise MirrorListError(
            f"payloads must be a non-empty list drawn from {', '.join(PAYLOADS)}: {payloads!r}\n"
            "  A mirror that serves nothing is one every client probes and never uses.")
    seen = set()
    for p in payloads:
        if not isinstance(p, str) or p not in PAYLOADS:
            raise MirrorListError(
                f"payloads may only contain {', '.join(PAYLOADS)}: {p!r}")
        if p in seen:
            raise MirrorListError(f"payloads lists {p!r} twice")
        seen.add(p)


def _no_duplicate_keys(pairs):
    """json.load's default keeps the LAST of two identical keys, so a file carrying `base_url`
    twice publishes one of them and shows the reviewer the other."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise MirrorListError(f"duplicate key {k!r}")
        out[k] = v
    return out


def load_entry(path):
    """Read and check one mirrors.d file. Raises with the path named."""
    stem, ext = os.path.splitext(os.path.basename(path))
    try:
        with open(path, encoding="utf-8") as fh:
            entry = json.load(fh, object_pairs_hook=_no_duplicate_keys)
    except MirrorListError as e:
        raise MirrorListError(f"{path}: {e}") from None
    except (OSError, ValueError) as e:
        raise MirrorListError(f"{path}: not readable as JSON: {e}") from None
    try:
        check_entry(entry, stem=stem)
    except MirrorListError as e:
        raise MirrorListError(f"{path}: {e}") from None
    return entry


def load_dir(dirpath):
    """Every registration in `dirpath`, in filename order.

    An EMPTY directory is valid and means what it says: the publisher states there are no mirrors.
    A MISSING one is not -- it is a checkout that did not produce what this producer reads, and
    treating it as "no mirrors" would quietly unpublish every mirror at once.
    """
    if not os.path.isdir(dirpath):
        raise MirrorListError(
            f"no such directory: {dirpath}\n"
            "  An absent registration directory is a broken checkout, not an empty list.")
    names = sorted(os.listdir(dirpath))          # never the OS's order: it is not stable
    # Dotfiles are SKIPPED rather than counted stray, and that is what makes "no mirrors yet"
    # expressible at all: git cannot track an empty directory, while an ABSENT one is a hard failure
    # just above (rightly -- it means a broken checkout), so the empty state can only be held open
    # by a placeholder like `.gitkeep`. Nothing is lost by ignoring them: a dotfile could never be a
    # registration, because `name` must match NAME_RE, which cannot begin with a dot, and the
    # filename has to equal `name`.
    names = [n for n in names if not n.startswith(".")]
    stray = [n for n in names if not n.endswith(".json")]
    if stray:
        raise MirrorListError(
            f"{dirpath} holds files that are not .json: " + ", ".join(repr(n) for n in stray) +
            "\n  A registration saved under any other extension is simply never published, and "
            "nothing downstream reports it.")
    return [load_entry(os.path.join(dirpath, n)) for n in names]


# --- the document -------------------------------------------------------------------------------

def build(entries, serial, signed_at=None):
    """The mirror list document. Pure: no clock, no filesystem, no network.

    `signed_at` is never defaulted to "now" -- taking the clock here would make two runs over
    unchanged input produce different bytes, and byte-identical output is what lets a reviewer
    confirm that a diff in the published list is exactly the diff in mirrors.d. The caller that
    knows a publish is happening (the publish workflow) supplies the instant; a local or
    pull-request build simply omits the key.
    """
    if isinstance(serial, bool) or not isinstance(serial, int):
        # bool is a subclass of int in Python, and `True` would render as `true` -- a JSON boolean
        # where every reader expects a number. Same trap release-tooling's Int/Enum guard against.
        raise MirrorListError(f"serial must be an integer, not {type(serial).__name__}")
    if not 0 <= serial <= U64_MAX:
        raise MirrorListError(f"serial must be a u64 (0..{U64_MAX}): {serial}")
    if signed_at is not None and (not isinstance(signed_at, str)
                                  or not SIGNED_AT_RE.match(signed_at)):
        raise MirrorListError(f"signed_at must look like 2026-09-01T11:00:00Z: {signed_at!r}")

    by_name, by_url = {}, {}
    for entry in entries:
        check_entry(entry)
        name, url = entry["name"], entry["base_url"]
        if name in by_name:
            raise MirrorListError(f"two mirrors are named {name!r}")
        by_name[name] = entry
        # Case-folded: a host name is case-insensitive, so two entries differing only in case are
        # one mirror to every resolver -- probed twice, ranked twice, and counted twice against the
        # primary.
        if url.casefold() in by_url:
            raise MirrorListError(
                f"mirrors {by_url[url.casefold()]!r} and {name!r} publish the same base_url {url!r}")
        by_url[url.casefold()] = name

    doc = {
        "format": FORMAT,
        "payload_id": PAYLOAD_ID,
        "serial": serial,
    }
    if signed_at is not None:
        doc["signed_at"] = signed_at
    # Sorted by name, not by input order: the output must depend on the SET of registrations and
    # nothing else, so that an unchanged mirrors.d re-renders byte for byte.
    doc["mirrors"] = [
        {
            "base_url": e["base_url"],
            "name": e["name"],
            "country": e["country"],
            "payloads": [p for p in PAYLOADS if p in e["payloads"]],
        }
        for _, e in sorted(by_name.items())
    ]
    return doc


def render(doc):
    """The exact bytes that get signed. LF, two-space indent, UTF-8, one trailing newline -- the
    same framing release-tooling's build_manifest.write uses, so every signed document this project
    publishes looks the same in a diff and in a hexdump."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def write(path, text):
    out_dir = os.path.dirname(os.path.abspath(path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


# --- has anything actually changed? ---------------------------------------------------------------

# The two fields that differ on EVERY publish by construction and say nothing about the list:
# `serial` rises once per publish, and `signed_at` is the clock. Comparing documents without
# excluding them would report "changed" always, which is the same as not comparing at all.
VOLATILE = ("serial", "signed_at")


def differs(published, candidate):
    """Do these two mirror lists say anything different?

    The question the publish workflow asks before it seals: every publish puts the release signing
    key into a CI runner, so a push that changes no mirror must not sign anything. Getting this
    wrong is expensive in one direction and merely wasteful in the other -- a false "unchanged" is a
    registration that merged green and silently never shipped, which is the failure this whole
    module exists to refuse -- so the caller treats "I could not tell" as neither answer and fails.

    It lives HERE, beside the renderer, because it is a fact about the FORMAT: which fields carry
    meaning and which are bookkeeping is the same knowledge `build` uses to emit them. A copy of
    that list in a shell pipeline would be free to drift from the document it describes.

    `mirrors` order is significant and deliberately so: `build` sorts by name, so the order is a
    function of the content -- two orderings mean two different published documents.
    """
    strip = lambda d: {k: v for k, v in d.items() if k not in VOLATILE}   # noqa: E731
    return strip(published) != strip(candidate)


def load_json(path):
    """A document to compare, read strictly. Malformed is an ERROR, never "assume it changed": the
    caller must be able to tell "these differ" from "I could not read one of them"."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise MirrorListError(f"{path}: not readable as a mirror list: {e}") from None


# --- selftest -----------------------------------------------------------------------------------

DEFAULT_DIR = "mirrors.d"
DEFAULT_OUT = "mirrors.json"


def _selftest():
    """The refusals are the point: each one is a well-formed registration that would publish a
    mirror no client ever uses, with nothing downstream able to notice."""
    import tempfile

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                      # noqa: BLE001 -- any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def refused(name, fn):
        try:
            fn()
        except MirrorListError as e:
            results.append((True, name, str(e).splitlines()[0]))
        except Exception as e:                      # noqa: BLE001
            results.append((False, name, f"raised {type(e).__name__}, not MirrorListError: {e}"))
        else:
            results.append((False, name, "ACCEPTED — the check does not exist"))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    def entry(**over):
        e = {"base_url": "https://mirror.example", "name": "phx-fi-1", "country": "FI",
             "payloads": ["mod", "launcher", "game"]}
        e.update(over)
        return e

    def other(**over):
        return entry(**{"base_url": "https://two.example", "name": "phx-ru-1", "country": "RU",
                        "payloads": ["mod"], **over})

    # --- the document it produces
    ok("a one-mirror list renders exactly the documented shape",
       lambda: assert_(build([entry()], 1) == {
           "format": 1, "payload_id": "mirrors", "serial": 1,
           "mirrors": [{"base_url": "https://mirror.example", "name": "phx-fi-1",
                        "country": "FI", "payloads": ["mod", "launcher", "game"]}]},
           f"unexpected document: {build([entry()], 1)!r}"))
    ok("an empty mirrors.d is a valid list — the publisher stating there are none",
       lambda: assert_(build([], 1)["mirrors"] == [], "an empty list was not rendered"))
    ok("signed_at is absent, not null, when none is supplied",
       lambda: assert_("signed_at" not in build([entry()], 1), "signed_at appeared unbidden"))
    ok("signed_at is carried through verbatim when supplied",
       lambda: assert_(build([entry()], 1, "2026-09-01T11:00:00Z")["signed_at"]
                       == "2026-09-01T11:00:00Z", "signed_at was rewritten"))
    ok("serial 0 is a u64", lambda: build([entry()], 0))
    ok("the largest u64 is a serial", lambda: build([entry()], U64_MAX))

    # --- determinism: the same set in any order is the same bytes
    ok("mirror order follows the name, not the input order",
       lambda: assert_(render(build([entry(), other()], 1)) == render(build([other(), entry()], 1)),
                       "input order reached the output"))
    ok("payloads are emitted in the format's order, not the input's",
       lambda: assert_(build([entry(payloads=["game", "mod"])], 1)["mirrors"][0]["payloads"]
                       == ["mod", "game"], "input order reached the output"))
    ok("two renders of one input are byte-identical",
       lambda: assert_(render(build([entry(), other()], 1))
                       == render(build([entry(), other()], 1)), "render is not a function"))

    # --- the URL rule, against the launcher's own canonical form
    ok("the launcher's canonical form agrees on a good URL",
       lambda: assert_(launcher_canonical("https://mirror.example") == "https://mirror.example",
                       "canonical form disagrees"))
    refused("http:// — stricter here than in the launcher, deliberately",
            lambda: build([entry(base_url="http://mirror.example")], 1))
    refused("a trailing slash, which the launcher would strip",
            lambda: build([entry(base_url="https://mirror.example/")], 1))
    refused("surrounding whitespace, which the launcher would trim",
            lambda: build([entry(base_url=" https://mirror.example")], 1))
    refused("a scheme with nothing after it",
            lambda: build([entry(base_url="https://")], 1))
    refused("no scheme at all",
            lambda: build([entry(base_url="mirror.example")], 1))
    refused("a non-ASCII host that was never punycoded",
            lambda: build([entry(base_url="https://зеркало.example")], 1))
    refused("a base_url that is not a string",
            lambda: build([entry(base_url=None)], 1))

    # --- identity and uniqueness
    refused("two mirrors with one name", lambda: build([entry(), entry()], 1))
    refused("two mirrors publishing one base_url",
            lambda: build([entry(), other(base_url="https://mirror.example")], 1))
    refused("one base_url differing only in case",
            lambda: build([entry(), other(base_url="https://MIRROR.example")], 1))
    refused("an uppercase name", lambda: build([entry(name="PHX-FI-1")], 1))
    refused("a name starting with a dash", lambda: build([entry(name="-fi")], 1))
    refused("an empty name", lambda: build([entry(name="")], 1))

    # --- fields
    refused("a lowercase country", lambda: build([entry(country="fi")], 1))
    refused("a three-letter country", lambda: build([entry(country="FIN")], 1))
    refused("an empty payloads list", lambda: build([entry(payloads=[])], 1))
    refused("an unknown payload", lambda: build([entry(payloads=["shim"])], 1))
    refused("a payload listed twice", lambda: build([entry(payloads=["mod", "mod"])], 1))
    refused("payloads given as a bare string", lambda: build([entry(payloads="mod")], 1))
    refused("a missing key", lambda: build([{k: v for k, v in entry().items() if k != "country"}], 1))
    refused("a typo'd key beside the real ones",
            lambda: build([dict(entry(), payload=["mod"])], 1))
    refused("a mirror that is not an object", lambda: build(["https://mirror.example"], 1))

    # --- the serial
    refused("a negative serial", lambda: build([entry()], -1))
    refused("a serial above u64", lambda: build([entry()], U64_MAX + 1))
    refused("a serial that is a bool (True == 1 in Python)", lambda: build([entry()], True))
    refused("a serial that is a string", lambda: build([entry()], "1"))
    refused("a malformed signed_at", lambda: build([entry()], 1, "2026-09-01 11:00"))

    # --- has anything actually changed? the question that decides whether CI signs at all, so a
    #     false "no" is a registration that merged green and never shipped
    ok("the same list is unchanged",
       lambda: assert_(not differs(build([entry()], 1), build([entry()], 1)), "reported a change"))
    ok("a rising serial alone is not a change",
       lambda: assert_(not differs(build([entry()], 1), build([entry()], 99)), "the serial leaked"))
    ok("a different signed_at alone is not a change",
       lambda: assert_(not differs(build([entry()], 1, "2026-01-01T00:00:00Z"),
                                   build([entry()], 2, "2026-09-09T09:09:09Z")),
                       "the clock leaked into the comparison"))
    ok("signed_at present vs absent is not a change",
       lambda: assert_(not differs(build([entry()], 1), build([entry()], 1, "2026-09-01T11:00:00Z")),
                       "an absent advisory field read as a change"))
    ok("adding a mirror IS a change",
       lambda: assert_(differs(build([entry()], 1), build([entry(), other()], 1)),
                       "a new mirror would never have been published"))
    ok("removing a mirror IS a change",
       lambda: assert_(differs(build([entry(), other()], 1), build([entry()], 1)),
                       "a retired mirror would never have been withdrawn"))
    ok("changing one field of one mirror IS a change",
       lambda: assert_(differs(build([entry()], 1), build([entry(country="SE")], 1)),
                       "an edited registration would never have shipped"))
    ok("a different payload set IS a change",
       lambda: assert_(differs(build([entry()], 1), build([entry(payloads=["mod"])], 1)),
                       "a mirror that dropped a payload would still be advertised for it"))

    # --- the directory, which needs real files
    with tempfile.TemporaryDirectory() as tmp:
        def put(fname, text):
            with open(os.path.join(tmp, fname), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            return os.path.join(tmp, fname)

        put("phx-fi-1.json", json.dumps(entry()))
        ok("a well-formed registration loads from disk",
           lambda: assert_(load_dir(tmp)[0]["name"] == "phx-fi-1", "entry did not round-trip"))

        put("phx-ru-1.json", json.dumps(entry(name="phx-fi-2")))
        refused("a file whose name and `name` field disagree", lambda: load_dir(tmp))
        os.remove(os.path.join(tmp, "phx-ru-1.json"))

        put("phx-ru-1.jsn", "{}")
        refused("a registration saved with the wrong extension", lambda: load_dir(tmp))
        os.remove(os.path.join(tmp, "phx-ru-1.jsn"))

        put("phx-ru-1.json", '{"base_url": "https://a.example", "base_url": "https://b.example",'
                             ' "name": "phx-ru-1", "country": "RU", "payloads": ["mod"]}')
        refused("a file carrying one key twice", lambda: load_dir(tmp))
        os.remove(os.path.join(tmp, "phx-ru-1.json"))

        put("phx-ru-1.json", "{not json")
        refused("a file that is not JSON at all", lambda: load_dir(tmp))
        os.remove(os.path.join(tmp, "phx-ru-1.json"))

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        ok("an empty registration directory loads as an empty list",
           lambda: assert_(load_dir(empty) == [], "an empty directory did not load"))

        # The state this repo actually ships in until a mirror exists. git cannot track an empty
        # directory, and a MISSING one is refused below, so without this the "no mirrors yet" list
        # is unpublishable and CI fails on a checkout that is perfectly correct.
        with open(os.path.join(empty, ".gitkeep"), "w", encoding="utf-8") as fh:
            fh.write("")
        ok("a .gitkeep holding the directory open is skipped, not called stray",
           lambda: assert_(load_dir(empty) == [], "the placeholder was treated as a registration"))

    refused("a registration directory that does not exist",
            lambda: load_dir(os.path.join("no", "such", "dir")))

    # --- and the repo's own registrations, which are the thing that actually ships
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_DIR)
    if os.path.isdir(here):
        ok(f"this repo's own {DEFAULT_DIR}/ builds",
           lambda: assert_(build(load_dir(here), 1)["payload_id"] == PAYLOAD_ID, "wrong payload_id"))

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


# --- CLI ----------------------------------------------------------------------------------------

def die(msg) -> NoReturn:
    """Annotated NoReturn so a reader — and a type checker — can see that no partly-built list is
    ever written: a refusal ends the run before anything reaches disk."""
    sys.exit("mirror-list: " + msg)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="render mirrors.d/ into a mirror list document")
    b.add_argument("--serial", required=True, type=int,
                   help="this list's place in its own order; the publisher decides the number "
                        "(see .github/workflows/publish.yml)")
    b.add_argument("--mirrors-dir", default=DEFAULT_DIR,
                   help="directory of per-mirror registrations (default: %(default)s)")
    b.add_argument("--out", default=DEFAULT_OUT, help="output path (default: %(default)s)")
    b.add_argument("--signed-at", help="advisory publish instant, e.g. 2026-09-01T11:00:00Z; "
                                       "omitted from the document when not given")

    c = sub.add_parser("changed", help="does a candidate list differ from the published one?")
    c.add_argument("--published", required=True, help="the currently published mirrors.json")
    c.add_argument("--candidate", required=True, help="the freshly built one")

    sub.add_parser("selftest", help="check the refusal rules against each other")
    a = ap.parse_args()

    if a.cmd == "selftest":
        sys.exit(1 if _selftest() else 0)

    if a.cmd == "changed":
        # Prints `true`/`false` for a shell to capture, and EXITS NON-ZERO on anything it could not
        # read. A caller must be able to tell the two apart: an exit code alone would make "they are
        # the same" and "I could not tell" the same event, and one of those must never be believed.
        try:
            verdict = differs(load_json(a.published), load_json(a.candidate))
        except MirrorListError as e:
            die(str(e))
        print("true" if verdict else "false")
        return

    try:
        doc = build(load_dir(a.mirrors_dir), a.serial, a.signed_at)
    except MirrorListError as e:
        die(str(e))
    text = render(doc)
    write(a.out, text)
    print(f"mirror-list: {a.out} — serial {doc['serial']}, {len(doc['mirrors'])} mirror(s), "
          f"{len(text.encode('utf-8'))} bytes")
    for m in doc["mirrors"]:
        print(f"  {m['name']:<16} {m['country']}  {m['base_url']}  [{' '.join(m['payloads'])}]")


if __name__ == "__main__":
    main()
