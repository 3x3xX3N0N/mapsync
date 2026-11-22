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
                    top_root  ──► anchor publicly (timestamp) = the outside witness
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
and leave the index ahead of the log head.

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
`vocab`, `world`, `signing`, `index`, `identity`, `proofs`, `sync`, `log`, `demo`, `g1`). Tests in `tests/` use
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
- **Keys.** Lost or stolen keys, rotation, and revocation aren't handled, for owners or
  agents. An agent's key changing today means a "new" agent.
- **Cross-key forgery isn't in `g1`.** The sandbox has no private keys, so "Alice's Cody
  signs Bob's node" was checked by hand (it goes red), not automatically.
- **Anchoring isn't automated.** `top_root` is printed. Publishing it is up to you.
- **The log can be withheld or rewritten whole.** `log/roots.jsonl` (see "History") makes
  quiet edits to the past break the chain, but whoever keeps it can still skip publishing
  an entry, or rewrite history and re-link every later line. Both show up only when someone
  runs `log compare` against a copy they kept (or an anchored head). Nobody signs log
  entries yet, and nobody is forced to keep a copy.

## Lineage

Same shape as [BikeChainz](https://github.com/3x3xX3N0N/BikeChainz): hashes certify
what's beneath them, the head can't certify itself, every green ships with a control
that makes it red, and trust at the top comes from outside readers.
