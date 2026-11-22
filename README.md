# mapsync

**The problem: everyone carries a mental map of the project, and nobody can prove the maps match.**

## The problem

Every person, and now every AI agent, working on something keeps a private map of it:
who is doing what, what was decided, what is done, what something is called. Work
goes wrong in the gaps between those maps:

- **Same thing, different words.** One person's "Review readiness" is another's "PR
  check". Two maps describe the same thing and look unrelated.
- **Same word, different things.** "Cody" is an agent in one map and a person in
  another. Two maps look aligned and aren't.
- **No proof of who said what, when.** "I told you on Tuesday" can't be checked. Maps
  get quietly rewritten after the fact, by accident or not.
- **No cheap way to ask "are we in sync?"** Today you find out by talking it through,
  or by shipping the wrong thing.

The obvious fix is one super repo that holds the one true map, and it fails. If
everyone edits a single map, nobody owns any part of it, conflicts are settled by
whoever merged last, and whoever runs the repo can rewrite history. The super repo
ends up certifying itself, and a system can't vouch for its own top.

## The approach: an index of maps, not one merged map

Three layers, each solving one part:

| layer | answers | how |
|---|---|---|
| **ownership** | whose claim is this? | each person keeps their own map; only they write it |
| **integrity** | is it unaltered since time X? | each map hashes to a Merkle root; the owner signs it |
| **meaning** | do two maps mean the same thing? | every node is tagged with a [SUMO](https://github.com/ontologyportal/sumo) term |

```
                    top_root  ──► log/roots.jsonl ──► witnesses sign receipts (anchors/)
                   /    |    \
         alice root   bob root   sumo-terms sha     ◄── index.json: signed roots only
          /  |  \       /  |  \
       nodes ...      nodes ...                     ◄── each person's own map.json
```

- **Sync check is one comparison.** Same top root means everyone holds identical maps.
  A different top root: walk down to the person, then the node, that differs.
- **Provenance.** Every node traces to a root its owner signed. Nobody, including
  whoever runs the index, can change someone's map without the signature breaking.
- **Meaning lines up across vocabularies.** People keep their own labels. The SUMO tag
  is the shared layer, so "Release note" and "Changelog" (both `Text`) land together,
  and a label used for two different SUMO terms shows up as a collision instead of
  merging silently.
- **The vocabulary is pinned.** The hash of the allowed SUMO term list goes into every
  root. If someone swaps the dictionary, every root changes. Meanings can't drift
  without anyone noticing.
- **Privacy.** Each node has a random salt, so a published root reveals nothing, and
  short hidden content can't be guessed by hashing candidates.

### The two-Codys problem: names are labels, keys are identities

Two people each have an AI agent (a familiar) called **Cody**. Both are tagged
`ComputerProgram`. Match on name or SUMO term and they merge: work for one shows up
under the other, and "Cody said X" can't be traced. The reverse failure also happens:
one agent called "Cody" in one place and "the coder" in another gets split in two.

The rule: **a label is a nickname you pick; identity is a key.**

- **Owner scoping.** Every node lives under its owner's signed map, so the identity is
  `alice:cody`, not `cody`, the way two Codys get different email domains.
- **Each agent has its own key.** An agent node carries `pubkey`. The owner signing the
  map is the owner saying "this key is my agent, and I call it Cody."
- **Agents sign their own work.** A node with `by: "cody"` must carry a signature from
  *that agent's* key (`agent_sigs/<node>.sig`). The owner can't fake it, and neither can
  the other Cody: a node signed by Alice's Cody fails as Bob's Cody.
- **Same thing only by explicit, signed link.** `same_as: ["bob:prcheck"]` says "my node
  is that node." One side only = **claimed**; both sides = **linked**. SUMO says two
  things are the same *kind*; only `same_as` says they're the same *thing*. Nothing
  is ever inferred from matching names.

```
$ python3 mapsync.py names
'cody'       alice:cody [key b35d00c4]  vs  bob:cody [key a8dad593]  -> COLLISION: same name, different identities
-- same_as links across different labels:
   alice:notes -> bob:changelog  CLAIMED (one side only)
   alice:review -> bob:prcheck  LINKED
   bob:prcheck -> alice:review  LINKED
```

This is Zooko's triangle: a name can't be readable, globally unique, *and* free of a
central registry at once. Keys are unique without a registry but unreadable; "Cody" is
readable but not unique. Use both, and let the key be the one that counts.

### The part hashing can't do

A hash tree proves everything *below* the top. Nothing inside it can prove the top.
That needs an outside witness: publish `top_root` somewhere the publisher doesn't
control (a public timestamp service, a blockchain, a post others archived, or just
each participant keeping their own copy). That witness is what turns "this is our map"
into "this was our map at time X."

## Try it

Stdlib Python 3 plus `ssh-keygen` (for signatures). No dependencies.

```bash
python3 mapsync.py verify     # every map signed by its owner, index matches a rebuild and is the log head
python3 mapsync.py g1         # sabotage each check in a sandbox; every one must go red
python3 mapsync.py concepts   # line the maps up by meaning, not by label
python3 mapsync.py names      # same name, different identity? (the two Codys)
python3 mapsync.py diff maps/alice/map.json maps/bob/map.json
```

`concepts` on the two example maps:

```
ComputerProgram      alice:'Psyche', alice:'Cody', bob:'Cody', bob:'the router'
IntentionalProcess   alice:'Review readiness', bob:'PR check'
Text                 alice:'Release note', bob:'Changelog'
TimeInterval         bob:'Ship date'
```

`g1` exists because a check that can't fail proves nothing. Each row breaks one thing
(a word of content, a SUMO tag, a salt, the owner name, swapped signatures, the pinned
term list, the index) and requires `verify` to go red. Further rows tamper with a proof
(revealed node, audit-path hash, a left/right flag, the claimed owner) and require
`check-proof` to go red, and change one node in a copy of the world and require
`sync-check` to name it. Log rows rewrite, drop and reorder past entries of the root log,
and leave the index ahead of the log head. Key rows forge the key chain (see "Keys").

### Add your own map

```bash
ssh-keygen -t ed25519 -f ~/.ssh/mapsync_me               # once
echo "me $(cut -d' ' -f1,2 ~/.ssh/mapsync_me.pub)" >> allowed_signers
mkdir maps/me && $EDITOR maps/me/map.json                # same shape as the examples
python3 mapsync.py sign maps/me/map.json ~/.ssh/mapsync_me
python3 mapsync.py log append && python3 mapsync.py verify   # rebuild index + record it in the log
```

A node is `{id, label, sumo, content, salt}`, plus optionally `pubkey` (this node is an
agent), `by` (an agent in this map wrote it) and `same_as` (list of `owner:id`). Use a
fresh random `salt` per node. An agent signs what it wrote with
`python3 mapsync.py agent-sign maps/me/map.json NODE AGENT_KEY`, then the owner re-signs
the map.

### Prove one node, reveal nothing else (selective disclosure)

`prove OWNER NODE` writes a self-contained JSON proof that a node is in its owner's signed
map, and under `top_root`, without handing over the rest of the map:

```bash
python3 mapsync.py prove alice review -o review.proof.json
python3 mapsync.py check-proof review.proof.json            # VALID ..., exit 0 (1 if invalid)
python3 mapsync.py check-proof review.proof.json --signers THEIR_allowed_signers --top-root HEX
```

The proof holds the revealed node; its leaf hash; the Merkle audit path from that leaf to
the map root (sibling hashes, each flagged `L`/`R`), plus a second path for the map head
(`{owner, sumo_terms_sha}`, leaf 0); the leaf index and count; the owner's `root.sig`; the
pinned term list; and the owner's index entry with its path (and the term-list sha's path)
up to `top_root`. `check_proof` rebuilds everything from the proof alone and runs
`ssh-keygen -Y verify` against the allowed_signers file *you* trust. It needs no other node,
and no access to the world. The flags have to match what `merkle()` builds for that
index and count, including the odd-level rule (a lone last hash pairs with itself), so a
path can't be reshuffled. The other nodes show up only as hashes, and their salts mean you
can't guess their content. What does leak: the leaf count (how many nodes) and the node's
position in id order. A node written by an agent is revealed with its `by` field, but the
proof doesn't carry the agent's own signature (`verify` checks that on the full world).
`top_root` is only as good as your copy of it: pin the one you anchored with `--top-root`.

### Are we in sync? Walk down

```bash
python3 mapsync.py sync-check /path/to/their/world      # or their index.json; exit 0 if in sync
python3 mapsync.py sync-check WORLD_A WORLD_B            # compare two others
```

Same `top_root`: `IN SYNC`. Otherwise it walks down: vocabulary changed, owners only here
(`-`) or only there (`+`), owners whose root changed (`~`) and, when both sides have the maps,
which node ids differ (`~ alice:review  differs`, the same logic as `diff`). An owner
with the same root but a new signature shows as re-signed. A world whose `index.json`
doesn't match its own maps gets a warning. `sync-check` compares what was published.
`verify` is what checks the signatures.

### History: an append-only log of top roots

`index.json` only shows the current state. `log/roots.jsonl` keeps every top root that was
published, one canonical JSON line per state (`sort_keys`, no spaces):

```
{"maps":[{"owner":"alice","root":"656b…"},{"owner":"bob","root":"2ea2…"}],"prev":"0000…","recorded_at":"2026-11-20T04:17:24Z","seq":0,"sumo_terms_sha":"e48a…","top_root":"5063…"}
```

Each line's `prev` is `sha256(0x02 || previous line's bytes)` (64 zeros for seq 0), so every
entry commits to the whole history before it. Change a past entry, drop one or reorder them,
and every later `prev` stops matching.

```bash
python3 mapsync.py log append                 # publish: rebuild index.json if stale, append if top_root changed
python3 mapsync.py log show                   # seq, time, top_root, entry sha, owners' roots
python3 mapsync.py log verify                 # chain intact and head == index.json; exit 0 if so
python3 mapsync.py log compare THEIR_roots.jsonl   # OK if one is a prefix of the other; FORK at seq N = exit 1
```

- **`log append` is how you publish a new state.** It refuses if any owner signature or
  identity check fails. It is idempotent: an unchanged top_root appends nothing. `index`
  still works, but it only rebuilds `index.json` and warns that the new state isn't
  published yet.
- **`verify` checks the log too.** If `log/roots.jsonl` exists, the chain must be intact
  (`seq` 0,1,2,… contiguous, each `prev` correct, every line canonical) and the head must
  record exactly the current `index.json` (top_root, owners' roots, vocabulary). Otherwise
  it reports `RED  current index is not the log head`. A world without a log gets a note
  and stays green, so older worlds keep verifying.
- **Forks.** Two honest copies of a log differ only in length: one is a prefix of the
  other. Anything else means someone showed different histories to different people, and
  `log compare` names the first `seq` where they diverge. Keep a copy of the log (or anchor
  its head) to catch a rewrite. A log that's been rewritten and re-chained is internally
  consistent, so only a comparison with an old copy can expose it.

`g1` builds a two-entry history in its sandbox (alice alone, then alice and bob). It then
rewrites a past entry, drops one, reorders them, and leaves the index ahead of the log
head, and `verify` has to go red for each.

### Anchoring: witnesses sign receipts for log entries

The log proves nothing about *when*, and whoever keeps it can rewrite it whole and re-link
every line. Anchoring answers "this was our map at time X": a **witness** (anyone whose
public key is listed in `witnesses`, same format as `allowed_signers`) signs a receipt for
one log entry with namespace `mapsync-anchor`:

```
anchors/<seq>-<top_root[:16]>-<witness>.json
{"version": 1, "witness": "w1", "log_seq": 0, "entry_sha": "a397…", "top_root": "5063…",
 "witnessed_at": "2026-11-20T04:23:03Z", "statement_sha": "26b8…", "sig": "-----BEGIN SSH SIGNATURE-----…"}
```

The signed statement is the canonical JSON (`sort_keys`, no spaces) of every field except
`sig` and `statement_sha`; `statement_sha` is its sha256. `entry_sha` pins the whole log line,
and through its `prev`, all history before it.

```bash
python3 mapsync.py anchor WITNESS KEY [--seq N]       # witness signs a receipt for the log head (or seq N)
python3 mapsync.py anchor verify [--min-witnesses K]  # every receipt valid? head has >= K witnesses? (default K=0)
python3 mapsync.py anchor export DIR                  # copy log + receipts + witnesses: your own copy
python3 mapsync.py log compare DIR/log/roots.jsonl    # later: has the log been rewritten since?
```

- **`anchor` refuses** if `log verify` fails, the entry doesn't exist, the witness isn't
  listed, or KEY isn't that witness's key.
- **A receipt is valid** when its file name matches its contents, `statement_sha` matches,
  the signature is by the key listed for *that* witness name (a receipt by A relabelled as B
  fails), and the log still holds the same `entry_sha` and `top_root` at `log_seq`.
  `anchor verify` reports each receipt and the number of distinct witnesses per log entry.
  It exits 1 if any receipt is invalid or the head has fewer than K witnesses.
- **`verify` checks receipts too** when `anchors/` exists. An invalid receipt is RED. An
  unwitnessed head is only a note, since a new state can't be witnessed before it exists.
  A receipt whose `seq`/`top_root`/`entry_sha` is no longer in the log is RED: history was
  rewritten (or truncated) after it was witnessed, even if the rewriter re-chained every
  line. That's the "this was our map at time X" guarantee.
- **Keep your own copy.** A rewriter can delete receipts along with history. A witness
  who ran `anchor export` still holds the old log and their receipt, so `log compare`
  against that copy reports the fork, and `--base DIR anchor verify` re-checks the copy on
  its own.

**Local witnesses, not public timestamps.** A receipt is only as good as the witness: it
shows that a key you chose to trust signed this entry, and `witnessed_at` is the witness's
own clock. It isn't a public timestamp. Nothing is published to a transparency log,
blockchain or RFC 3161 timestamp authority. That's out of scope by operator decision
(no network). Several independent witnesses who each keep an export get you most of the way:
rewriting history then needs every one of them to collude or lose their copy.

**Shipped example:** the repo ships one demo receipt, `anchors/0-5063e96c07099d44-demo-witness.json`,
for log seq 0. It was signed by a throwaway `demo-witness` key generated in `/tmp`. Only the
public key is committed (in `witnesses`); the private key was deleted right after signing and
never entered the repo. It exists so `verify` exercises the receipt path on the shipped
world. Nobody can sign as `demo-witness` again, so treat it as an example, not a trust root.
To witness for real, add your own `name ssh-ed25519 …` line to `witnesses` and run `anchor`.

`g1` builds a two-entry history witnessed by two fresh keys (`w1`, `w2`) in its sandbox. It
backdates a receipt's `witnessed_at` (recomputing `statement_sha`, so only the signature can
catch it), rewrites seq 0 and re-chains the log after it was anchored, relabels w1's receipt
as w2's, and adds a receipt signed by an unlisted key. `verify` has to go red for each.

### Keys: rotation, revocation, recovery; identity is the key lineage

Keys get lost, stolen and replaced. If identity were "the current key", a rotated Cody would
be a new Cody. So identity is the **lineage**: the chain of keys an owner or agent has had,
named by the fingerprint of its *first* key. Rotate Alice's Cody three times and `names`
still says `alice:cody [key b35d00c4, rotated 3 times]`, still distinct from Bob's Cody.

Each owner may keep `maps/<owner>/keys.jsonl`, an append-only hash-chained event log (no
file = keys are exactly what `allowed_signers` and the maps' `pubkey` fields say, as
before). One canonical JSON line per event:

```
{"at":"2026-11-20T04:30:29Z","new_key":"ssh-ed25519 AAAA…","old_key":"ssh-ed25519 AAAA…","prev":"0000…","reason":"rotate","seq":0,"sigs":{"old":"-----BEGIN SSH SIGNATURE-----…","owner":"…"},"subject":"agent:cody","type":"rotate"}
```

`prev` is `sha256(0x03 || previous line)`; each entry in `sigs` is an ssh signature
(namespace `mapsync-keys`) over the line without `sigs`, by the key its role names:
`owner` (the owner's current key), `old` (`old_key`), `new` (`new_key`) or `recovery`.

| event | subject | who must sign |
|---|---|---|
| `recovery` | owner | owner; replacing an existing recovery key also needs the old recovery key |
| `rotate` | owner | new key **and** the old key (or the recovery key). Once the owner key is revoked, only recovery + new |
| `rotate` | `agent:<id>` | owner (optionally also the old/new agent key); the node's `pubkey` becomes `new_key` and the owner re-signs the map |
| `revoke` | owner or `agent:<id>` | owner (current, unrevoked key) or recovery; `old_key` = the key revoked, current or retired |

```bash
python3 mapsync.py keys show alice                                   # events, lineages, chain head
python3 mapsync.py keys recovery alice ALICE_KEY RECOVERY.pub        # pre-register a recovery key
python3 mapsync.py keys rotate alice agent:cody NEW.pub --sign ALICE_KEY --sign OLD_CODY_KEY
python3 mapsync.py keys rotate alice owner NEW.pub --sign ALICE_KEY --sign NEW_KEY   # updates allowed_signers, re-signs
python3 mapsync.py keys revoke alice agent:cody OLD_CODY.pub --by owner --signer ALICE_KEY
python3 mapsync.py keys revoke alice owner STOLEN.pub --by recovery --signer RECOVERY_KEY
python3 mapsync.py keys rotate alice owner NEW.pub --sign RECOVERY_KEY --sign NEW_KEY   # after a lost/stolen owner key
python3 mapsync.py keys verify                                       # every chain; exit 0 if green
python3 mapsync.py index && python3 mapsync.py log append           # publish the new chain
```

`--sign` keys are matched to roles by their public key. A command refuses (and writes
nothing) if the resulting chain wouldn't verify. What `verify` checks when a chain exists:

- **The chain is intact and authorised.** `seq` contiguous, `prev` correct, lines
  canonical, every signature valid for its role, every event signed by who the table says,
  no key reused. A forged, reordered or dropped line, or a rotation that the old key didn't
  sign, is RED.
- **Owner:** `root.sig` must verify under the *current* owner key at the chain head, that
  key must not be revoked, and `allowed_signers` must hold that same key (a mismatch is RED).
- **Agents:** the node's `pubkey` must be the lineage's current key. A node signature counts
  if it's by the current key *or a retired (rotated) one*: rotation is honest, so old
  signatures stay green. A signature by a **revoked** key is RED (treated as compromised)
  until the node is re-signed with the current key.
- **Published:** when a chain exists, the owner's index entry gains `keys_sha` (sha256 of
  `keys.jsonl`), so the chain is under `top_root` and goes into the log with it. Maps
  without a chain hash exactly as before; the shipped roots and top root are unchanged.

The owner's first key is the `old_key` of the first owner rotate/revoke line, or
`allowed_signers` if there is none. An agent's first key is the `old_key` of its first line.

**Limits, honestly:**
- **Whoever holds the recovery key wins.** A thief with only the owner key can rotate it,
  but recovery can revoke the thief's key and rotate past it, and the thief can't replace
  the recovery key. A thief with the owner key *and* the recovery key owns the identity.
  Lose both and the identity is gone; start a new lineage.
- **No trusted time.** `at` is the signer's own clock. The order of events is the chain's
  order; published via `log append` (and anchored, if you use witnesses), that's the only
  "when". A retired key that is stolen later can still make signatures that look old, which
  is why `revoke` works on retired keys too.
- **Revocation is retroactive.** Revoking a key turns *everything* it signed red, including
  honest signatures made before the theft, since there's no trusted time to tell them
  apart. Re-sign with the current key.
- **The chain can be withheld or forked** like the root log: whoever hosts `keys.jsonl` can
  show an older chain. Compare logs (or anchors) to catch it; `keys_sha` makes any change
  visible in `top_root`.
- **The first key is trusted on first use.** Nothing outside `allowed_signers` (or the
  first chain line) vouches for it.

`g1` builds a freshly keyed world in its sandbox, rotates Alice's Cody and registers a
recovery key (green), then: an owner rotation signed only by the new key, revoking Cody's
old key while its signatures remain, a forged chain line, reordered chain lines, and
`allowed_signers` disagreeing with the chain head. `verify` has to go red for each.

### Other worlds, demo worlds, tests

Every command takes a global `--base DIR` (default: this repo), the world to work on.
`demo DIR` builds a complete signed world shaped like the example (alice, bob, two
unrelated Codys, agent-signed nodes, `same_as` links) with fresh throwaway ed25519 keys in
`DIR/keys/`, so you can sign, break and re-sign things without the example's private
keys, which aren't in the repo.

```bash
python3 mapsync.py demo /tmp/w                 # fresh keys + signed maps + index.json
python3 mapsync.py --base /tmp/w verify        # green
python3 mapsync.py --base /tmp/w g1            # same sabotage rows, on that world
python3 -m unittest discover tests             # the test suite (stdlib unittest)
```

Code layout: `mapsync.py` is the CLI only; the logic is in `mapsynclib/` (`hashing`,
`vocab`, `world`, `signing`, `index`, `identity`, `keys`, `proofs`, `sync`, `log`, `anchor`, `demo`, `g1`). Tests in `tests/` use
`mapsynclib.demo.make_world(dir)` for anything that needs a private key.

## Open problems (not solved here)

- **SUMO's upper terms are coarse.** `concepts` above lumps the coordinator and both
  Codys together as `ComputerProgram`. Real use needs SUMO's mid-level and
  domain terms (MILO and others), or local subclasses declared on top of SUMO.
- **Tagging is work.** Nobody will hand-pick from tens of thousands of terms. The
  realistic path is a suggester (WordNet→SUMO mappings, or an LLM) proposing a tag and a
  human confirming it.
- **Disagreement isn't a sync failure.** Two maps can both be valid and still contradict.
  The goal is that everyone sees the same *set of signed claims*, side by side and
  attributed, not that a merge picks a winner. Contradiction checks would need a
  reasoner over SUMO's axioms (e.g. Sigma), which this prototype doesn't do.
- **Key compromise is bounded, not solved.** Rotation, revocation and recovery exist (see
  "Keys"), but a thief holding both the owner and recovery keys wins, there's no trusted
  time, and revoking a key reddens its honest past signatures too.
- **Cross-key forgery isn't in `g1`.** The sandbox has no private keys, so "Alice's Cody
  signs Bob's node" was checked by hand (it goes red), not automatically.
- **Witnesses are local, not public.** Anchoring (see "Anchoring") has witnesses sign
  receipts locally. No public timestamp or transparency log is involved, by operator
  decision. A rewrite that also deletes the receipts shows up only against a witness's
  exported copy, and nobody is forced to keep one.
- **The log can be withheld.** Whoever keeps `log/roots.jsonl` can still skip publishing an
  entry. Witnesses can only sign what they're shown.

## Lineage

Same shape as [BikeChainz](https://github.com/3x3xX3N0N/BikeChainz): hashes certify
what's beneath them, the head can't certify itself, every green ships with a control
that makes it red, and trust at the top comes from outside readers.
