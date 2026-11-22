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
    alice · bob · carol roots   terms sha   vocab sha   ◄── index.json: signed roots only
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
  without anyone noticing. A pinned subclass hierarchy with local subclasses and
  disjointness axioms sits on top (see "Vocabulary").
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
python3 mapsync.py concepts   # line the maps up by meaning, not by label (a subclass tree)
python3 mapsync.py vocab CodingAgent   # where a term sits: ancestors, subclasses, disjoint classes
python3 mapsync.py names      # same name, different identity? (the two Codys)
python3 mapsync.py suggest Release note   # offline tag suggestions (a human confirms with `tag ... --yes`)
python3 mapsync.py claims     # same_as clusters side by side: AGREE / REFINES / CONTRADICTION
python3 mapsync.py diff maps/alice/map.json maps/bob/map.json
```

Every command, in one place (each section below explains its part). All of them take the
global `--base DIR` (default: this repo):

```bash
# maps and signatures
python3 mapsync.py root MAP                       # a map's Merkle root
python3 mapsync.py sign MAP KEY                   # owner signs the root -> root.sig
python3 mapsync.py agent-sign MAP NODE AGENTKEY   # the agent itself signs a node it wrote
python3 mapsync.py index                          # rebuild index.json (top_root)
python3 mapsync.py verify                         # check everything; exit 0 if green
python3 mapsync.py diff A.json B.json             # which nodes differ between two maps
# identity and meaning
python3 mapsync.py names                          # same label, different key? (two Codys)
python3 mapsync.py concepts [--flat]              # maps lined up by SUMO term, as a subclass tree
python3 mapsync.py vocab [TERM]                   # validate the pinned hierarchy / place one term
python3 mapsync.py suggest TEXT...                # top-5 SUMO terms for TEXT (offline lexicon)
python3 mapsync.py suggest --map MAP              # each node's tag vs the top suggestion
python3 mapsync.py tag MAP NODE TERM [--yes]      # retag a node (only with --yes; never signs)
python3 mapsync.py claims [--json] [--redact] [--strict]   # AGREE / REFINES / CONTRADICTION
# proofs and sync
python3 mapsync.py prove OWNER NODE [-o FILE]     # inclusion proof revealing just that node
python3 mapsync.py check-proof FILE [--signers F] [--top-root H]   # check a proof on its own
python3 mapsync.py sync-check OTHER [SECOND]      # same top root? else walk down to owner, node
# history and witnesses
python3 mapsync.py log append | log show | log verify   # the hash-chained log of top roots
python3 mapsync.py log compare OTHER_LOG          # prefix = consistent; else FORK at seq N
python3 mapsync.py anchor WITNESS KEY [--seq N]   # a witness signs a receipt for a log entry
python3 mapsync.py anchor verify [--min-witnesses K]   # receipts valid; head has >= K witnesses
python3 mapsync.py anchor export DIR              # a participant's own copy of log + receipts
# keys
python3 mapsync.py keys show OWNER                # key chain and lineages
python3 mapsync.py keys recovery OWNER OWNER_KEY RECOVERY_PUB [--sign OLD_RECOVERY_KEY]
python3 mapsync.py keys rotate OWNER owner|agent:ID NEW_PUB --sign KEY [--sign KEY]
python3 mapsync.py keys revoke OWNER owner|agent:ID KEY --by owner|recovery --signer KEY
python3 mapsync.py keys verify                    # every key chain intact; exit 0 if green
# checking the checks
python3 mapsync.py g1 [--list]                    # run (or just list) every sabotage row
python3 mapsync.py demo DIR [--local-terms]       # a fresh signed world with throwaway keys
python3 -m unittest discover tests                # the test suite, incl. tests/test_e2e.py
```

`verify` never stops on a traceback: a missing file, invalid JSON, a map that isn't an
object, a node missing a field or carrying the wrong type all come out as `RED` with the
reason (file and field), and exit 1.

`concepts` on the example maps (alice and bob use base SUMO terms only; carol uses
local subclasses, marked `*`):

```
Process                        -  [4 in all]
  IntentionalProcess           alice:'Review readiness', bob:'PR check'  [4 in all]
    Communication              -  [1 in all]
      LinguisticCommunication* -  [1 in all]
        Directing*             -  [1 in all]
          Requesting*          carol:'Ask for review'
    Planning                   carol:'Sprint plan'
Proposition                    -  [6 in all]
  ComputerProgram              alice:'Psyche', alice:'Cody', bob:'Cody', bob:'the router'  [6 in all]
    CodingAgent*               carol:'Builder'
    RoutingAgent*              carol:'Switchboard'
Text                           alice:'Release note', bob:'Changelog'
TimeInterval                   bob:'Ship date'
```

Each used term sits under its ancestors from the pinned hierarchy, with the labels tagged
with exactly that term; `[N in all]` counts the nodes at or below it. `concepts --flat`
prints the old one-line-per-term output unchanged.

`g1` exists because a check that can't fail proves nothing. Each row breaks one thing
(a word of content, a SUMO tag, a salt, the owner name, swapped signatures, the pinned
term list, the index) and requires `verify` to go red. Further rows tamper with a proof
(revealed node, audit-path hash, a left/right flag, the claimed owner) and require
`check-proof` to go red, and change one node in a copy of the world and require
`sync-check` to name it. Log rows rewrite, drop and reorder past entries of the root log,
and leave the index ahead of the log head. Key rows forge the key chain (see "Keys").
Vocabulary rows edit `sumo/local.txt` under maps that use it, add a subclass cycle, an
unknown parent, a redefined base term, and a class under two disjoint classes (see
"Vocabulary"). Lexicon rows edit `sumo/lexicon.txt` or point a word at an unknown term,
and a claims row retags a linked pair with disjoint terms and requires `claims` to show
`CONTRADICTION` (see "Suggesting tags" and "Claims").

Forgery rows build a world with fresh throwaway keys (`demo.make_world`, in the sandbox,
deleted afterwards) so they can really sign the wrong thing: Alice's Cody signs Bob's node,
Bob's owner key signs Alice's root, an agent's `mapsync-agent` signature is put in as a
`root.sig`, an owner's signature is passed off as an anchor receipt, a key-chain event is
signed in the owner namespace. Each goes red. The four signing namespaces (`mapsync`
for owner roots, `mapsync-agent` for nodes, `mapsync-keys` for key events,
`mapsync-anchor` for receipts) are distinct, and the green controls next to the namespace
rows show it is the namespace alone that turns them red: the same key over the same
bytes, in the right namespace, passes. Audit rows cover the rest (`log compare` on a
forked copy, `anchor verify --min-witnesses` above what was signed, a lexicon weight of 0
or a duplicate entry, `tag --yes` without re-signing, `check-proof --top-root`, a missing
signer). `g1` ends with a summary line, e.g. `G1: 72 rows (55 sabotages, 17 green
controls), every sabotage went red, baseline green`; `g1 --list` prints the rows without
running them.

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

`g1` builds a two-entry history in its sandbox (alice alone, then the current index). It then
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

### Vocabulary: a pinned SUMO hierarchy, local subclasses, disjointness

`sumo/terms.txt` alone is flat and coarse: the coordinator and both Codys are all
`ComputerProgram`. Three more pinned files sit on top of it. `terms.txt` itself is
unchanged, since its sha is inside every shipped root.

| file | lines | rules |
|---|---|---|
| `sumo/hierarchy.txt` | `Child Parent` | SUMO subclass edges among base terms, curated from SUMO (`Planning IntentionalProcess`, `ComputerProgram Proposition`, ...). Several parents allowed. |
| `sumo/local.txt` | `NewTerm Parent` | local subclasses (`CodingAgent ComputerProgram`, `RoutingAgent ComputerProgram`) and a few SUMO mid-level terms marked `# from MILO/SUMO`. One parent each, base or local; must not redefine a base term. |
| `sumo/disjoint.txt` | `A B` | nothing is both an A and a B, inherited by every subclass. From SUMO's top partitions (Object vs Process vs Abstract). |

`#` starts a comment. The three files are validated together. A subclass cycle, an unknown
term or parent, a duplicate line, a redefined base term, or a class that ends up under two
disjoint classes makes `vocab` and `verify` go red. `mapsynclib.vocab` exposes
`load_vocab(base)` plus `ancestors(term)`, `is_a(a, b)` and `disjoint(a, b)`, all
respecting inheritance (the disjointness checks in later cards use these).

**Pinning stays backward compatible.** `vocab_sha` is sha256 over
`mapsync-vocab/1\n` followed by each of hierarchy, local and disjoint as
`<name>.txt <len>\n<bytes>` (a missing file counts as 0 bytes).

- A map whose nodes all use base terms hashes its head as `{owner, sumo_terms_sha}`, exactly
  as before. alice's and bob's roots (`656b6e9d…`, `2ea2aa8c…`) and signatures are unchanged,
  and editing the hierarchy files doesn't touch them.
- A map that tags any node with a local term adds `vocab_sha` to its head. Its owner then
  signs the whole hierarchy, so any edit to those files, even a comment, changes that map's
  root and turns `verify` red until the owner re-signs. A tag that is neither a base term nor
  a valid local term is red as before.
- The index commits to `vocab_sha` whenever the files exist: it's an extra key in
  `index.json`, an extra leaf of the top tree after the terms sha, and a `vocab_sha` field
  in new log entries. `sync-check` reports `! vocabulary hierarchy differs`. Inclusion proofs
  carry the hierarchy files and their audit path, so a node tagged `CodingAgent` proves
  on its own.

```bash
python3 mapsync.py vocab                     # validate; counts and vocab_sha
python3 mapsync.py vocab CodingAgent         # is a: ComputerProgram -> Proposition; disjoint with ...
python3 mapsync.py concepts                  # tree; --flat for the old output
python3 mapsync.py demo /tmp/w --local-terms # Codys tagged CodingAgent, routers RoutingAgent
```

**Shipped example:** `carol` is a third owner whose map uses local terms (`RoutingAgent`,
`CodingAgent`, `Requesting`) plus base `Planning`, so her root pins `vocab_sha`. Her map was
signed with a throwaway key generated in `/tmp`. Only the public key is in `allowed_signers`;
the private key was deleted right after signing and never entered the repo, so nobody can
re-sign carol's map. Adding carol and the hierarchy moved the top root to `258d5f37…`, which
is log seq 1. The demo receipt still covers seq 0 (`5063e96c…`, alice and bob only), and
seq 1 isn't witnessed yet (a note, not red).

The hierarchy is still curated by hand. The edges are a small, deliberately chosen part
of SUMO (intermediate classes are collapsed and named in comments), not SUMO's full
axioms.

### Suggesting tags: an offline lexicon, and a human who says yes

Nobody picks from thousands of SUMO terms by hand, so `suggest` proposes tags and a person
confirms them. It is offline and deterministic: no LLM, no network, no randomness.

`sumo/lexicon.txt` holds lines `word Term [weight]` (weight defaults to 1), in the spirit of
the WordNet→SUMO mappings but hand-curated: 139 entries covering every base and local term.
Text and lexicon words are both stemmed the simple way (lowercase, strip plural s/es, -ing,
-ed, then a trailing e and a doubled final consonant: note/notes, plan/planning, ship/shipped
meet). Every lexicon hit adds its weight to its term. Ties go to the more specific term (more
ancestors in the pinned hierarchy), then alphabetically. Each Term must be a base or local
term, a word can't be listed twice for one term, and a bad line is red in `verify`.

The lexicon is pinned like the hierarchy. `lexicon_sha` (plain sha256 of the file) is a key
in `index.json`, the last leaf of the top tree, and a field in new log entries. Proofs carry
it with its audit path. Map roots don't depend on it, so editing the lexicon changes only
`top_root` and needs `index` + `log append`; until then `verify` is red. Adding it moved the
shipped top root to `49cc8207…` (log seq 2). alice, bob and carol's roots are unchanged.

```bash
python3 mapsync.py suggest Cody coding agent   # top 5: Term score (ancestors)
python3 mapsync.py suggest --map bob           # each node: its tag vs the top suggestion
python3 mapsync.py tag bob deadline Event      # says what it would do; writes nothing
python3 mapsync.py tag bob deadline Event --yes   # writes the tag, then reminds you to re-sign
```

```
CodingAgent               3  (ComputerProgram -> Proposition)
ComputerProgram           1  (Proposition)
Agent                     1  (top)
```

```
bob:cody          tag ComputerProgram     suggest CodingAgent 3   related
bob:orchestrator  tag ComputerProgram     suggest RoutingAgent 3  related
bob:prcheck       tag IntentionalProcess  suggest Requesting 4    related
bob:changelog     tag Text                suggest Text 5          same
bob:deadline      tag TimeInterval        suggest TimeInterval 4  same
```

`suggest --map` marks `same`, `related` (one is_a the other) or `MISMATCH?` (unrelated: worth
a look, not an error). `tag` writes only with `--yes` and **never signs**. Afterwards
`verify` is red until the owner re-signs the map (`sign`), and, if the node has `by`, the
agent re-signs its node first (`agent-sign`). Then run `index` and `log append`. Retagging
a base-tagged map with a local term also makes its head pin `vocab_sha`.

### Claims: disagreement side by side, not a sync failure

Two maps can both be validly signed and still say different things about the same thing.
`claims` doesn't pick a winner. It shows everyone's signed claims side by side, each one
attributed.

Nodes joined by `same_as` (LINKED, CLAIMED, either way an edge) form identity clusters, the
connected components. Each member shows `owner:id`, label, SUMO tag, content (`<hidden>`
with `--redact`), its author (`by` agent with its key lineage id, or the owner), and the
signed map root it sits in. Each pair in a cluster gets one verdict:

| verdict | meaning |
|---|---|
| `AGREE` | same term |
| `REFINES` | one is_a the other: one claim is just more specific |
| `CONTRADICTION` | the terms are disjoint (`sumo/disjoint.txt`, inherited) |
| `DIFFERENT KIND` | none of these (or a term the vocabulary doesn't know) |

```bash
python3 mapsync.py claims             # text; --json for machines; --redact hides content
python3 mapsync.py claims --strict    # exit 1 if any CONTRADICTION (CI-style gate)
```

```
cluster 1: alice:notes, bob:changelog
  alice:notes    'Release note'  Text  'Draft of what shipped this week'
                 by agent alice:cody [key b35d00c4]; in alice's root 656b6e9d362ee0bb… (signed)
  bob:changelog  'Changelog'     Text  'Draft of what shipped this week'
                 by agent bob:cody [key a8dad593]; in bob's root 2ea2aa8c1191e1d9… (signed)
  alice:notes ~ bob:changelog  CLAIMED: AGREE  (both Text)
cluster 2: alice:review, bob:prcheck
  alice:review  'Review readiness'  IntentionalProcess  'Check a change is ready for review'
                by agent alice:cody [key b35d00c4]; in alice's root 656b6e9d362ee0bb… (signed)
  bob:prcheck   'PR check'          IntentionalProcess  'Make sure a pull request is good to go'
                by owner bob; in bob's root 2ea2aa8c1191e1d9… (signed)
  alice:review ~ bob:prcheck  LINKED: AGREE  (both IntentionalProcess)
2 cluster(s): 2 AGREE, 0 REFINES, 0 CONTRADICTION, 0 DIFFERENT KIND
```

A pair that is only in the same cluster through others is marked `via cluster`. A
contradiction is a finding: nothing is merged, both claims stay signed as they are, and
`verify` stays green (a test retags alice:review `Human` and bob:prcheck `ComputerProgram`,
re-signs, and gets `CONTRADICTION`, `claims --strict` exit 1, `verify` exit 0).

**This is a lexicon plus a disjointness check over a small pinned hierarchy, not a SUMO
reasoner.** It knows subclass edges and declared disjoint pairs, nothing else. It doesn't
reason over SUMO's axioms, relations or rules the way Sigma does, so many real
contradictions (in content, numbers, time) go unseen.

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
`vocab` (terms, hierarchy, concepts), `world`, `signing`, `index`, `identity`, `keys`, `proofs`, `sync`, `log`, `anchor`, `suggest`, `claims`, `demo`, `g1`). Tests in `tests/` use
`mapsynclib.demo.make_world(dir)` for anything that needs a private key.

## What's solved / what's still open

**Solved here** (each with a `g1` row that turns it red):

- **Is this map unaltered, and whose is it?** Merkle roots signed by the owner; the
  owner's name and the pinned vocabulary are inside the signed bytes.
- **Two Codys.** Identity is a key, not a label. Agents sign their own nodes; a node
  signed by the wrong agent, by another owner, or in the wrong namespace is red.
- **Same thing, different words.** SUMO tags line maps up by kind; only a signed
  `same_as` says two nodes are the same thing. `claims` shows linked nodes side by side.
- **Are we in sync?** One comparison of top roots, then a walk down to owner and node.
- **Show one node, hide the rest.** Inclusion proofs check on their own.
- **History.** An append-only, hash-chained log of top roots; dropping, reordering or
  rewriting entries is red, and `log compare` names the seq where two copies fork.
- **"This was our map at time X", locally.** Witnesses sign receipts for log entries; a
  rewrite after the fact leaves receipts pointing at something no longer there.
- **Lost or stolen keys, bounded.** Rotation, revocation and a pre-registered recovery
  key, with one stable lineage per identity.
- **Meaning drift.** The term list, hierarchy, local subclasses, disjointness axioms and
  the suggester's lexicon are all pinned under `top_root`.

**Still open** (not solved here, some by design):

- **No public anchoring, by design.** Witnesses are local keys signing local receipt
  files; no public timestamp service, transparency log or blockchain is involved. A
  rewrite that also deletes every receipt shows up only against a witness's exported
  copy, and nobody is forced to keep one.
- **Witnesses' clocks are trusted.** `witnessed_at` is whatever the witness's clock said.
  Receipts order entries only as far as you trust the witnesses not to lie about time,
  and colluding witnesses can backdate together.
- **The collector can withhold.** Whoever keeps `log/roots.jsonl` and `index.json` can
  skip publishing an entry, or leave a map out. Witnesses can only sign what they're
  shown; absence isn't detectable without an outside expectation of what should be there.
- **No full SUMO reasoner.** `claims` catches only tags declared disjoint in a small
  pinned hierarchy. A reasoner over SUMO's axioms (e.g. Sigma) would find much more, and
  nothing here sees disagreement in free-text content.
- **Suggestions are only as good as a small lexicon.** `suggest` is a hand-curated word
  list, not WordNet's full mapping or a language model. A human confirms every tag.
- **Key compromise is bounded, not solved.** A thief holding both the owner and the
  recovery key wins; there's no trusted time to say a signature predates a compromise,
  so revoking a key reddens its honest past signatures too.
- **Agreement isn't truth.** Two signed, linked, in-sync maps can both be wrong. mapsync
  proves who claimed what and when they agreed, not that the claim is right.

## Lineage

Same shape as [BikeChainz](https://github.com/3x3xX3N0N/BikeChainz): hashes certify
what's beneath them, the head can't certify itself, every green ships with a control
that makes it red, and trust at the top comes from outside readers.
