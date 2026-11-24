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
python3 mapsync.py verify     # every map signed by its owner, index matches a rebuild
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
term list, the index) and requires `verify` to go red.

### Add your own map

```bash
ssh-keygen -t ed25519 -f ~/.ssh/mapsync_me               # once
echo "me $(cut -d' ' -f1,2 ~/.ssh/mapsync_me.pub)" >> allowed_signers
mkdir maps/me && $EDITOR maps/me/map.json                # same shape as the examples
python3 mapsync.py sign maps/me/map.json ~/.ssh/mapsync_me
python3 mapsync.py index && python3 mapsync.py verify
```

A node is `{id, label, sumo, content, salt}`, plus optionally `pubkey` (this node is an
agent), `by` (an agent in this map wrote it) and `same_as` (list of `owner:id`). Any other
field is allowed and kept, and it is hashed and signed like the rest: there are no
unsigned fields, at node or map level (`g1` checks that adding one goes red). Use a
fresh random `salt` per node. An agent signs what it wrote with
`python3 mapsync.py agent-sign maps/me/map.json NODE AGENT_KEY`, then the owner re-signs
the map.

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
- **Who collects the roots.** Anyone can rebuild `index.json` from the maps and check it,
  so whoever runs it is a messenger, not an authority. Making it append-only (a log of
  past top roots) is the next step.

## Lineage

Same shape as [BikeChainz](https://github.com/3x3xX3N0N/BikeChainz): hashes certify
what's beneath them, the head can't certify itself, every green ships with a control
that makes it red, and trust at the top comes from outside readers.
