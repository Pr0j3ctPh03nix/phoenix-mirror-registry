#!/usr/bin/env python3
"""Register a mirror by PULLING its entry from the host, and opening the pull request yourself.

    python register_mirror.py https://mirror.example
    python register_mirror.py selftest

WHY IT PULLS. The mirror software can open its own registration pull request (`register.ts` on the
host), but only with a registry credential sitting on the box. If that credential is the operator's
own PAT it is write access to `main` of this repo — the branch that SIGNS AND PUBLISHES — parked on
a public-facing machine that exists to serve strangers gigabytes. A self-operated mirror should hold
no registry credential at all. So the host instead SERVES its entry at `<base_url>/register.json` —
byte for byte the contents of `mirrors.d/<name>.json`, derived from the config that host is actually
running. This script fetches it and turns it into a branch pushed with the OPERATOR's own git
identity — no token, no `gh`, no API call. Git and a browser.

WHAT IT REFUSES, and why each refusal is not politeness:
  * a working tree that is not a clean checkout of this repo on `main` -- the commit it makes has to
    be one file on top of the published list, and anything else lands unrelated work in a
    registration a reviewer is reading as "one added file";
  * an entry `generate_mirror_list.py` would refuse -- checked HERE, through that module's own
    `check_entry`, so a registration cannot be merged and then fail the publish it was merged for;
  * an entry whose `base_url` is not the URL it was fetched from -- a host may register ITSELF and
    nothing else. Without that, a host asked about could name someone else's URL and this script
    would faithfully propose it.

WHAT IT DOES NOT DECIDE. Nothing here is a check on whether a mirror is trustworthy: that is the
pull request review, and it is the only check that matters (see `generate_mirror_list.py`). This
script's whole job is to make the reviewable thing -- one added file -- without a credential.

Stdlib only, like the generator it imports, and for the same reason: `selftest` runs on a pull
request from a fork with no install step. The network and git are each behind ONE function, which
is what lets that selftest exercise every refusal with neither.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
import webbrowser
from typing import NoReturn

# The generator is the authority on what an entry may contain, and it is imported rather than
# restated: every rule below that looks like a rule about entries is a call into that module. It
# sits beside this file, which is `sys.path[0]` when this file is the script being run.
import generate_mirror_list as mirror_list

# --- what this script talks to ------------------------------------------------------------------

# What the host serves, relative to its `base_url`. The mirror writes it from its own config, so
# fetching it asks the host what it IS rather than what somebody transcribed about it.
REGISTER_PATH = "register.json"

# A registration is four short strings. The cap is enormous for that and still small enough that a
# host answering with a disk image costs nothing: the body is read at cap+1 and refused, never
# buffered whole. The timeout is the same shape of decision -- a mirror that cannot answer in ten
# seconds is not one to send clients to.
MAX_BODY = 64 * 1024
TIMEOUT = 10

# Named so a mirror operator reading their own access log can tell this apart from a client.
UA = "phoenix-register-mirror"

# The branch this repo publishes from (see .github/workflows/publish.yml), which is therefore both
# the branch a registration must be based on and the base of the compare link. One fact, one place.
MAIN = "main"


class RegisterError(Exception):
    """Something this script refuses to turn into a pull request. `MirrorListError` is the other
    half -- the generator's own refusals, raised with the generator's own wording, deliberately not
    re-worded here -- and the CLI reports the two identically."""


# Both are refusals to the operator, never tracebacks: the generator's rules are as much a reason
# not to open a pull request as this script's own.
REFUSALS = (RegisterError, mirror_list.MirrorListError)


# --- the URL ------------------------------------------------------------------------------------

def canonical_base_url(url):
    """The command line's URL in the one form this registry publishes, or a refusal.

    NORMALISING here is the opposite of the rule the generator applies to a file, and both are
    right: a `mirrors.d` entry must ALREADY be canonical (the published string is what every future
    reader receives), while a URL typed at a shell may reasonably carry the trailing slash a browser
    put there. So this passes the argument through the launcher's own canonical form first, then
    through the generator's check -- which is what refuses http://, non-ASCII and an empty host with
    the generator's own message.
    """
    if not isinstance(url, str):
        raise RegisterError(f"a base URL must be a string, not {type(url).__name__}")
    # `launcher_canonical` answers None for "not a URL at all"; handing check_base_url the trimmed
    # original then produces the message that names what is actually wrong with it.
    canonical = mirror_list.launcher_canonical(url) or url.strip()
    mirror_list.check_base_url(canonical)
    return canonical


# --- the fetch ----------------------------------------------------------------------------------

def http_get(url, timeout=TIMEOUT, cap=MAX_BODY):
    """The ONE function in this file that touches the network. Returns (status, final_url, body).

    It reads `cap + 1` bytes and hands back whatever came: deciding what is too large belongs to the
    caller, and reading one byte past the limit is what lets "too large" be told from "exactly the
    limit" without ever holding more than that.

    TLS IS VERIFIED, by urllib's default context, and there is deliberately no flag to turn that
    off. A mirror on a bare IP is not the exception it looks like -- a certificate with an IP SAN
    verifies normally -- and the one situation an insecure flag would help with, a host whose
    certificate does not match the URL being registered, is precisely a host that must not be
    published under that URL.
    """
    # This function is reached only through `canonical_base_url`, but it holds the scheme rule
    # itself: it is the seam every future caller will reach for, and `urlopen` will happily open a
    # file:// or ftp:// URL that got this far.
    if not url.startswith("https://"):
        raise RegisterError(f"refusing to fetch a non-https URL: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, res.url, res.read(cap + 1)
    except urllib.error.HTTPError as e:
        # urlopen raises on 4xx/5xx, so this is where "the host does not serve one" arrives.
        raise RegisterError(
            f"{url} answered HTTP {e.code} {e.reason}\n"
            "  A host registers by SERVING its entry there; if this mirror does not, it is running "
            "a version that predates that, or serving from a different root than it publishes.") \
            from None
    except (urllib.error.URLError, OSError) as e:
        raise RegisterError(f"{url} could not be fetched: {e}") from None


def entry_from_host(base_url):
    """The entry a host publishes about itself, checked by the generator before it is believed.

    `base_url` must already be canonical (`canonical_base_url`).
    """
    url = f"{base_url}/{REGISTER_PATH}"
    status, final_url, body = http_get(url)

    if status != 200:
        raise RegisterError(f"{url} answered HTTP {status}, not 200")
    # urllib follows redirects, and https -> http is one it will follow. The published entry names
    # ONE URL, so a hop that changed the scheme -- or the host -- has to be visible rather than
    # silently registered under the address that was typed.
    if not final_url.startswith("https://"):
        raise RegisterError(f"{url} redirected to a non-https URL: {final_url!r}")
    if len(body) > MAX_BODY:
        raise RegisterError(
            f"{url} answered with more than {MAX_BODY} bytes\n"
            "  A registration is four short strings; anything that size is not one.")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RegisterError(f"{url} did not answer with UTF-8 text: {e}") from None
    try:
        # The generator's own duplicate-key guard, not json's default: a body carrying `base_url`
        # twice would otherwise register one of them and show the reviewer the other.
        entry = json.loads(text, object_pairs_hook=mirror_list._no_duplicate_keys)
    except mirror_list.MirrorListError as e:
        raise mirror_list.MirrorListError(f"{url}: {e}") from None
    except ValueError as e:
        raise RegisterError(f"{url} is not JSON: {e}") from None

    # Every rule about what an entry may contain, applied by the module that owns them. The filename
    # is not checked here because it does not exist yet -- it is DERIVED from `name` below, so the
    # two cannot disagree.
    mirror_list.check_entry(entry)

    # A host may register ITSELF and nothing else. Without this, asking any host for its entry would
    # let it propose a registration for somebody else's URL, signed off by whoever ran this script.
    if entry["base_url"] != base_url:
        raise RegisterError(
            f"{url} publishes base_url {entry['base_url']!r}, not {base_url!r}\n"
            "  A host may only register the URL it was fetched from. If that is the address this "
            "mirror should be known by, register it with that URL; if the host is misconfigured, "
            "fix its config and re-run.")
    return entry


# --- the file it writes -------------------------------------------------------------------------

def render_entry(entry):
    """The bytes of `mirrors.d/<name>.json`.

    Rendered through the generator's own `render`, so the framing (2-space indent, LF, one trailing
    newline) is the one every signed document in this project uses -- and the one `register.ts`'s
    `renderEntry` already emits, so a host that serves canonical bytes sees this script write them
    back unchanged.

    Both orderings are the FORMAT's, never the host's: keys in `ENTRY_KEYS` order and payloads in
    `PAYLOADS` order, exactly as `build` will re-emit them. A file that recorded how a particular
    host happened to serialise its config would make two identical registrations two different
    diffs.
    """
    ordered = {k: entry[k] for k in mirror_list.ENTRY_KEYS}
    ordered["payloads"] = [p for p in mirror_list.PAYLOADS if p in entry["payloads"]]
    return mirror_list.render(ordered)


def read_text(path):
    """The file as it stands, or None when it is not there. Read as BYTES and decoded, never through
    universal newlines: the comparison this feeds is "are these the same bytes", and a CRLF copy is
    not."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RegisterError(f"{path} is not readable: {e}") from None
    return raw.decode("utf-8", errors="replace")


# --- git ----------------------------------------------------------------------------------------

def git(repo, *args):
    """Every git invocation in this file goes through here, and it is the seam `selftest` replaces.

    Returns (returncode, stdout, stderr), stripped, because every caller either wants one short line
    or wants to know whether it worked -- and a runner that raised could not express "this branch
    does not exist", which is a perfectly good answer.
    """
    proc = subprocess.run(("git",) + args, cwd=repo, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def git_step(repo, *args):
    """A git command that must succeed, quoting git's own complaint when it does not."""
    code, out, err = git(repo, *args)
    if code != 0:
        raise RegisterError(f"`git {' '.join(args)}` failed: {err or out or f'exit {code}'}")
    return out


# `git@github.com:o/r.git`, `https://github.com/o/r`, `ssh://git@github.com/o/r.git`, with or
# without the `.git` suffix and a trailing slash. Only github.com: the compare URL below is a
# github.com page, so a remote anywhere else is a repo this script cannot finish the job for.
ORIGIN_RE = re.compile(
    r"^(?:https://(?:[^@/]+@)?github\.com/|(?:ssh://)?git@github\.com[:/])"
    r"([^/]+)/(.+?)(?:\.git)?/?$")


def github_slug(url):
    """`owner/repo` from an origin URL, or None when it does not name one on github.com."""
    m = ORIGIN_RE.match(url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def compare_url(slug, branch):
    """The page that opens a pull request from `branch`. `branch` is `mirror-register-<name>` and
    `name` matches NAME_RE, so there is nothing here to escape."""
    return f"https://github.com/{slug}/compare/{MAIN}...{branch}?expand=1"


def check_checkout(repo):
    """Refuse anything but a clean checkout of this repo on `main`; answer with its GitHub slug.

    There is no `--allow-dirty`. A registration is meant to be read as one added file, and the way
    that stops being true is not a reviewer's mistake -- it is unrelated work carried into the
    commit by `git switch -c`, invisible in the pull request title and perfectly plausible in the
    diff.
    """
    code, top, err = git(repo, "rev-parse", "--show-toplevel")
    if code != 0:
        raise RegisterError(f"{repo} is not a git checkout: {err or f'exit {code}'}")
    try:
        same = os.path.samefile(top, repo)
    except OSError:
        same = False
    if not same:
        raise RegisterError(
            f"{repo} is not the root of its checkout (that is {top})\n"
            "  Run this script from the registry clone it lives in.")

    code, branch, err = git(repo, "symbolic-ref", "--short", "HEAD")
    if code != 0:
        raise RegisterError(f"HEAD is not on a branch (detached?): {err or f'exit {code}'}")
    if branch != MAIN:
        raise RegisterError(
            f"this checkout is on {branch!r}, not {MAIN!r}\n"
            f"  A registration branches from {MAIN}, which is what is published; branching from "
            "anything else proposes that other thing too.")

    code, dirty, err = git(repo, "status", "--porcelain")
    if code != 0:
        raise RegisterError(f"`git status` failed: {err or f'exit {code}'}")
    if dirty:
        raise RegisterError(
            "the working tree is not clean:\n" + textwrap.indent(dirty, "    ") +
            "\n  Commit, stash or discard these first — they would be carried onto the "
            "registration branch and into the pull request.")

    code, origin, err = git(repo, "remote", "get-url", "origin")
    if code != 0:
        raise RegisterError(f"this checkout has no `origin` remote: {err or f'exit {code}'}")
    slug = github_slug(origin)
    if slug is None:
        raise RegisterError(
            f"`origin` is {origin!r}, which does not name a github.com repository\n"
            "  The branch is pushed to origin and the pull request is opened on that "
            "repository, so this script cannot finish the job against any other host.")
    return slug


# --- the whole flow -----------------------------------------------------------------------------

def register(repo, arg_url):
    """Fetch, check, write, branch, commit, push. Returns the compare URL, or None when the entry
    was already published exactly as served.

    Opening a browser is NOT done here: it is the one step with no reason to run inside a test, and
    keeping it in `main` means the tested path is the whole path.
    """
    slug = check_checkout(repo)
    base_url = canonical_base_url(arg_url)
    entry = entry_from_host(base_url)

    name = entry["name"]
    rel = f"{mirror_list.DEFAULT_DIR}/{name}.json"
    path = os.path.join(repo, mirror_list.DEFAULT_DIR, f"{name}.json")
    text = render_entry(entry)
    print(f"register-mirror: {base_url}/{REGISTER_PATH} -> {rel}")
    print(textwrap.indent(text.rstrip("\n"), "  "))

    existing = read_text(path)
    if existing == text:
        print(f"register-mirror: {rel} already says exactly this — nothing to register.")
        return None

    # The branch check comes BEFORE anything is written, so a run this script was always going to
    # refuse leaves no file behind for the operator to clean up.
    branch = f"mirror-register-{name}"
    if git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}")[0] == 0:
        raise RegisterError(
            f"the branch {branch!r} already exists here\n"
            "  It is not reset: it may hold work that was never pushed. Delete it "
            f"(`git branch -D {branch}`) once you have looked at it, then re-run.")

    if existing is not None:
        # A re-registration: the host now serves something other than what is published. The diff in
        # the pull request is the whole story, so this only says which of the two cases it is.
        print(f"register-mirror: {rel} exists and differs — this is a re-registration.")

    mirror_list.write(path, text)
    # Read straight back through the generator's own loader — the same call the publisher makes.
    # This is what makes "the file this script wrote is a file `build` accepts" a fact rather than a
    # property of two renderers agreeing.
    mirror_list.load_entry(path)

    git_step(repo, "switch", "-c", branch)
    git_step(repo, "add", "--", rel)
    git_step(repo, "commit",
             "-m", f"mirror: register {name}",
             "-m", f"`{base_url}` — {entry['country']}, serving "
                   f"{', '.join(entry['payloads'])}.\n\n"
                   f"Pulled from {base_url}/{REGISTER_PATH} by register_mirror.py, so the entry is "
                   "what that host actually serves rather than a transcription of it.")
    git_step(repo, "push", "-u", "origin", branch)

    url = compare_url(slug, branch)
    print(f"\nPushed {branch}. Open the pull request:\n  {url}\n")
    print("Then: wait for `validate` to go green (it builds the list with your entry in it), and "
          "ask a\nmaintainer to review and merge. Merging to "
          f"{MAIN} is what publishes — `publish.yml` seals the\nnew list and releases it as the "
          "next serial.")
    return url


# --- selftest -----------------------------------------------------------------------------------

def _selftest():
    """The network and git are each one function, and both are replaced here — so every refusal is
    exercised with neither.

    GIT IS FAKED rather than driven against a scratch repository, and the trade is deliberate: what
    has to be proved is that the branch/commit/push sequence is ISSUED, in order, and only after the
    checks that can refuse — which a recorded call log states directly. A real repository would
    prove the same thing while also requiring `git` and a configured committer identity on every
    machine and CI runner this runs on, neither of which this script's rules depend on. (A real
    end-to-end push against a bare repo is a thing to do by hand once; it is not a unit test.)
    """
    import contextlib
    import io
    import tempfile

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                      # noqa: BLE001 -- any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def refused(name, fn, saying=None):
        """`saying` is a substring the refusal must carry — used where the POINT of the case is
        which module's message the operator sees."""
        try:
            fn()
        except REFUSALS as e:
            first = str(e).splitlines()[0]
            if saying is not None and saying not in str(e):
                results.append((False, name, f"refused, but not saying {saying!r}: {first}"))
            else:
                results.append((True, name, first))
        except Exception as e:                      # noqa: BLE001
            results.append((False, name, f"raised {type(e).__name__}, not a refusal: {e}"))
        else:
            results.append((False, name, "ACCEPTED — the check does not exist"))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    BASE = "https://mirror.example"

    def entry(**over):
        e = {"base_url": BASE, "name": "phx-fi-1", "country": "FI",
             "payloads": ["mod", "launcher", "game"]}
        e.update(over)
        return e

    def serving(body, status=200, final=None):
        """A stand-in for `http_get`: the same three values, from nowhere."""
        def fake(url, timeout=TIMEOUT, cap=MAX_BODY):
            return status, (final or url), body
        return fake

    def serves(entry_, **over):
        return serving(render_entry(entry_).encode("utf-8"), **over)

    @contextlib.contextmanager
    def stubbed(**names):
        """Swap module globals for the duration — how both seams are replaced."""
        saved = {k: globals()[k] for k in names}
        globals().update(names)
        try:
            yield
        finally:
            globals().update(saved)

    def fetch(fake, url=BASE):
        with stubbed(http_get=fake):
            return entry_from_host(canonical_base_url(url))

    # --- the URL the operator types
    ok("a trailing slash is normalised, not refused as it would be in a file",
       lambda: assert_(canonical_base_url("https://mirror.example/") == BASE, "not normalised"))
    ok("surrounding whitespace is trimmed",
       lambda: assert_(canonical_base_url("  https://mirror.example  ") == BASE, "not trimmed"))
    ok("several trailing slashes go too",
       lambda: assert_(canonical_base_url("https://mirror.example///") == BASE, "not stripped"))
    ok("an already-canonical URL is unchanged",
       lambda: assert_(canonical_base_url(BASE) == BASE, "canonical form is not a fixed point"))
    refused("http://, with the generator's own reason",
            lambda: canonical_base_url("http://mirror.example"), saying="must start with https://")
    refused("a URL with no scheme", lambda: canonical_base_url("mirror.example"))
    refused("a scheme with nothing after it", lambda: canonical_base_url("https://"))
    refused("a host that was never punycoded",
            lambda: canonical_base_url("https://зеркало.example"))

    # --- the fetch, with the network replaced
    ok("a host serving its own entry registers",
       lambda: assert_(fetch(serves(entry()))["name"] == "phx-fi-1", "the entry did not come back"))
    refused("a body over the cap", lambda: fetch(serving(b"x" * (MAX_BODY + 1))),
            saying="more than")

    def at_cap():
        # Padded with the whitespace JSON ignores, to exactly the cap: the refusal must be at
        # cap + 1, which is the byte `http_get` reads past the limit precisely to see.
        body = json.dumps(entry()).encode("utf-8")
        assert_(fetch(serving(body + b" " * (MAX_BODY - len(body))))["name"] == "phx-fi-1",
                "a body of exactly the cap was refused")

    ok("a body of exactly the cap is accepted — the refusal is at cap + 1", at_cap)
    refused("a non-200 answer", lambda: fetch(serves(entry(), status=204)), saying="not 200")
    refused("a redirect that dropped TLS",
            lambda: fetch(serves(entry(), final="http://mirror.example/register.json")),
            saying="non-https")
    refused("a body that is not UTF-8", lambda: fetch(serving(b'{"name": "\xff"}')),
            saying="UTF-8")
    refused("a body that is not JSON", lambda: fetch(serving(b"<html>404</html>")),
            saying="not JSON")
    refused("a body carrying one key twice",
            lambda: fetch(serving(b'{"base_url": "https://a.example",'
                                  b' "base_url": "https://mirror.example",'
                                  b' "name": "phx-fi-1", "country": "FI",'
                                  b' "payloads": ["mod"]}')),
            saying="duplicate key")

    # --- the generator's rules, applied here and reported in its words
    refused("an entry the generator refuses, with the generator's message",
            lambda: fetch(serves(entry(country="fi"))),
            saying="country must be a two-letter uppercase code")
    # Served RAW, not through `serves`: `render_entry` projects onto ENTRY_KEYS, so rendering the
    # body here would drop the very key the check is about before the check could see it.
    refused("an entry carrying a key nothing reads",
            lambda: fetch(serving(json.dumps(dict(entry(), payload=["mod"])).encode("utf-8"))),
            saying="unknown key")
    refused("a host registering somebody else's URL",
            lambda: fetch(serving(json.dumps(entry(base_url="https://other.example"))
                                  .encode("utf-8"))),
            saying="may only register the URL it was fetched from")

    # --- the bytes it writes
    ok("the rendered entry is what register.ts renders — 2-space, LF, one trailing newline",
       lambda: assert_(render_entry(entry()) == json.dumps(
           {"base_url": BASE, "name": "phx-fi-1", "country": "FI",
            "payloads": ["mod", "launcher", "game"]}, indent=2) + "\n",
           f"unexpected framing: {render_entry(entry())!r}"))
    ok("payloads are written in the format's order, not the host's",
       lambda: assert_(json.loads(render_entry(entry(payloads=["game", "mod"])))["payloads"]
                       == ["mod", "game"], "the host's order reached the file"))
    ok("keys are written in ENTRY_KEYS order",
       lambda: assert_(list(json.loads(render_entry(entry()))) == list(mirror_list.ENTRY_KEYS),
                       "key order is not the format's"))

    # --- the origin URL, which is where the compare link comes from
    ok("an https origin names its repository",
       lambda: assert_(github_slug("https://github.com/o/r.git") == "o/r", "slug not parsed"))
    ok("an ssh origin names the same repository",
       lambda: assert_(github_slug("git@github.com:o/r.git") == "o/r", "slug not parsed"))
    ok("an https origin without .git",
       lambda: assert_(github_slug("https://github.com/o/r") == "o/r", "slug not parsed"))
    ok("an ssh:// origin",
       lambda: assert_(github_slug("ssh://git@github.com/o/r.git") == "o/r", "slug not parsed"))
    ok("a non-GitHub origin names nothing",
       lambda: assert_(github_slug("https://gitlab.com/o/r.git") is None, "accepted another host"))
    ok("the compare URL for an https origin",
       lambda: assert_(compare_url(github_slug("https://github.com/o/r.git"),
                                   "mirror-register-phx-fi-1")
                       == "https://github.com/o/r/compare/main...mirror-register-phx-fi-1?expand=1",
                       "unexpected compare URL"))
    ok("the compare URL for an ssh origin is the same page",
       lambda: assert_(compare_url(github_slug("git@github.com:o/r.git"), "b")
                       == compare_url(github_slug("https://github.com/o/r.git"), "b"),
                       "the two origin forms disagree"))

    # --- the whole flow, with both seams replaced
    def run(repo, fake_http, *, branches=(), dirty="", branch=MAIN,
            origin="https://github.com/o/r.git", url=BASE + "/"):
        """One complete `register()`, answering git from a script instead of a process."""
        log = []

        def fake_git(cwd, *args):
            log.append(args)
            if args[:2] == ("rev-parse", "--show-toplevel"):
                return 0, repo, ""
            if args[:1] == ("symbolic-ref",):
                return (0, branch, "") if branch else (1, "", "not a symbolic ref")
            if args[:1] == ("status",):
                return 0, dirty, ""
            if args[:2] == ("remote", "get-url"):
                return (0, origin, "") if origin else (1, "", "No such remote")
            if args[:2] == ("rev-parse", "--verify"):
                return (0 if args[-1] in {f"refs/heads/{b}" for b in branches} else 1), "", ""
            return 0, "", ""

        out = io.StringIO()
        with stubbed(git=fake_git, http_get=fake_http), contextlib.redirect_stdout(out):
            result = register(repo, url)
        return result, out.getvalue(), log

    with tempfile.TemporaryDirectory() as tmp:
        state = {}

        def first_run():
            state["url"], state["out"], state["log"] = run(tmp, serves(entry()))

        ok("a registration runs end to end", first_run)
        mutating = [a for a in state.get("log", []) if a[0] in ("switch", "add", "commit", "push")]
        ok("the branch, the commit and the push are issued in that order",
           lambda: assert_([a[0] for a in mutating] == ["switch", "add", "commit", "push"],
                           f"the sequence was {[a[0] for a in mutating]!r}"))
        ok("the branch is named for the mirror, and is not forced",
           lambda: assert_(mutating[0] == ("switch", "-c", "mirror-register-phx-fi-1"),
                           f"unexpected branch step: {mutating[0]!r}"))
        ok("exactly the one registration file is staged",
           lambda: assert_(mutating[1] == ("add", "--", "mirrors.d/phx-fi-1.json"),
                           f"unexpected add: {mutating[1]!r}"))
        ok("the commit subject is the one register.ts also writes",
           lambda: assert_(mutating[2][:2] == ("commit", "-m")
                           and mutating[2][2] == "mirror: register phx-fi-1",
                           f"unexpected commit: {mutating[2]!r}"))
        ok("the commit body names the base URL and the country",
           lambda: assert_(BASE in mutating[2][-1] and "FI" in mutating[2][-1],
                           f"unexpected body: {mutating[2][-1]!r}"))
        ok("the branch is pushed to origin and tracked",
           lambda: assert_(mutating[3] == ("push", "-u", "origin", "mirror-register-phx-fi-1"),
                           f"unexpected push: {mutating[3]!r}"))
        ok("the compare URL is returned and printed",
           lambda: assert_(state["url"] == compare_url("o/r", "mirror-register-phx-fi-1")
                           and state["url"] in state["out"], "the compare URL was not reported"))

        # The written file is the actual product, so it is checked through the publisher's own path
        # rather than by comparing strings: `load_dir` + `build` is exactly what CI runs.
        ok("the file that was written is one the generator loads",
           lambda: assert_(mirror_list.load_entry(
               os.path.join(tmp, "mirrors.d", "phx-fi-1.json"))["base_url"] == BASE,
               "the written file did not load"))
        ok("and one that builds into a list",
           lambda: assert_(mirror_list.build(
               mirror_list.load_dir(os.path.join(tmp, "mirrors.d")), 1)["mirrors"][0]["name"]
               == "phx-fi-1", "the written file did not build"))

        def second_run():
            state["url2"], state["out2"], state["log2"] = run(tmp, serves(entry()))

        ok("running it again against an unchanged host does nothing", second_run)
        ok("an identical existing file opens no branch and pushes nothing",
           lambda: assert_(state["url2"] is None
                           and not [a for a in state["log2"]
                                    if a[0] in ("switch", "add", "commit", "push")],
                           f"it acted anyway: {state['log2']!r}"))
        ok("and says so",
           lambda: assert_("already says exactly this" in state["out2"], state["out2"]))

        # A host that changed what it serves IS a registration — the diff is the review.
        ok("a changed entry is proposed again",
           lambda: assert_(run(tmp, serves(entry(country="SE")), branches=())[0] is not None,
                           "a re-registration was treated as a no-op"))

        refused("a dirty working tree", lambda: run(tmp, serves(entry()), dirty=" M README.md"),
                saying="not clean")
        refused("a checkout on another branch",
                lambda: run(tmp, serves(entry()), branch="wip"), saying="not 'main'")
        refused("a detached HEAD", lambda: run(tmp, serves(entry()), branch=""))
        refused("an origin that is not on github.com",
                lambda: run(tmp, serves(entry()), origin="https://git.example/o/r.git"),
                saying="does not name a github.com repository")
        refused("no origin at all", lambda: run(tmp, serves(entry()), origin=""))
        refused("a registration branch that already exists",
                lambda: run(tmp, serves(entry(country="NO")),
                            branches=("mirror-register-phx-fi-1",)),
                saying="already exists")

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


# --- CLI ----------------------------------------------------------------------------------------

def die(msg) -> NoReturn:
    sys.exit("register-mirror: " + msg)


def main():
    # STDERR too, unlike the generator: every refusal in this file goes there, and this is the one
    # script an operator runs on their own Windows box, where the console encoding is not UTF-8 and
    # the refusal is the whole output they get.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # One positional, not a subcommand tree: the whole interface is a mirror's URL. `selftest` is
    # spelled as a value rather than a subparser because it cannot be confused with one -- a base
    # URL must start with https://.
    ap.add_argument("base_url", metavar="BASE_URL",
                    help="the mirror's base URL, e.g. https://mirror.example — its entry is read "
                         f"from <BASE_URL>/{REGISTER_PATH}. Or the literal `selftest`.")
    a = ap.parse_args()

    if a.base_url == "selftest":
        sys.exit(1 if _selftest() else 0)

    # The checkout this script edits is the one it lives in. There is no --repo: a second copy of
    # this file pointed at a different clone is a way to commit into the wrong one.
    repo = os.path.dirname(os.path.abspath(__file__))
    try:
        url = register(repo, a.base_url)
    except REFUSALS as e:
        die(str(e))
    if url is None:
        return
    # Best effort, and the URL is printed either way: a headless box, WSL without a browser handler,
    # or a plain SSH session all land here and none of them is a failed registration.
    try:
        webbrowser.open(url)
    except Exception:                       # noqa: BLE001 -- opening a browser cannot fail a run
        pass


if __name__ == "__main__":
    main()
