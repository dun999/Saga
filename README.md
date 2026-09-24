# Saga: agents that remember, chat that improve, on Walrus

Saga is a self-improving, multi-agent **harness** written in C++23. You plug in the coding agents you already
use, **Claude Code, Codex and Grok**, plus any **OpenAI-compatible API** (xAI, OpenRouter, Groq, Ollama,
llama.cpp). You then hand work between them with `@mentions`:

> build a landing page for my coffee cart, then **@codex** add a tiny API server for the menu, and **@grok** review both

Everything Saga learns is stored as encrypted blobs on **Walrus mainnet** through
[Walrus Memory (MemWal)](https://github.com/MystenLabs/MemWal). That covers who you are, what happened in past
tasks, per-agent lessons, reusable skills, the shared task blackboard and the evolving system prompt. The
harness ships **no database** and keeps no local state. Kill the process, boot it on another machine with
the same delegate key, and Saga still knows you.

Built for the Walrus **"Chatbots That Remember"** hackathon. The design draws on the YC Paper Club
*Harness Edition* reading list (see [Research lineage](#research-lineage)).

---

## What memory actually does here

| Memory (Walrus namespace) | Written when | Used when |
|---|---|---|
| `u:<you>:facts` | every message, via relayer-side fact extraction (`/api/analyze`); also 👍/👎 comments | recalled into every agent's context, so preferences apply without being restated |
| `u:<you>:episodes` | end of every turn | continuity ("last time we built X…") |
| `task:<turn>` | after every agent step | **cross-agent blackboard**: `@codex` sees what `@claude` built, and why |
| `agent:<name>:lessons` | reflection after 👍/👎 or an automatic failure | injected only into that agent's context (Reflexion) |
| `harness:skills` | a 👍 on a successful multi-step turn | recalled for similar future requests (Voyager) |
| `harness:prompts`, `harness:scores` | prompt evolution / every rating and credit tag | the system prompt (base + playbook rules) served each turn is Thompson-sampled from the live versions |
| `u:<you>:cases` | every rated turn, explicit or implicit | replayed to test a new prompt version before it goes live |

At boot Saga calls `restore()` on the hot namespaces. The relayer's vector index is only a cache, and
Walrus is the source of truth.

## The self-improvement loop

```
 user msg ─► recall facts / episodes / skills / lessons ─► assemble context (prompt vN) ─► @agents
    ▲                                                                                        │
    │        👍/👎 + comment                                                                  ▼
    └── Thompson-sample ◄── replay gate ◄── playbook edit ◄── critiques ◄── reflection ◄── trace
        live versions      (child vs parent,  (add/edit/remove              (brain)    + signals:
                           blind judge)        rules, ACE)                               👍/👎, "no, …",
                                                                                         "thanks", PR opened
```

* **Signals, not just thumbs**: a 👍/👎 counts, and so does what the user does next. A reply that
  starts with "no, …" or "that's wrong" is an implicit 👎 on the previous answer, "thanks" or "perfect"
  is an implicit 👍, and opening a pull request from a chat is a 👍 on its last turn. Every rated turn
  is kept as a replay case in the user's own namespace.
* **Reflexion**: each signal triggers a reflection pass. It writes lessons for the specific agent
  involved and says which playbook rules and lessons in context helped or hurt. A rule or lesson that
  hurts at least twice, and more often than it helps, stops being used.
* **Playbook, not rewrites** (ACE): the system prompt is a fixed base plus short rules. Every
  `SAGA_EVOLVE_EVERY` critiques (default 3), the brain proposes at most three add/edit/remove edits,
  so rules that work can't be lost in a rewrite.
* **Replay gate** (Darwin Gödel Machine, GEPA): before a new version serves anyone, it answers the
  user's own rated past messages next to its parent, and a judge picks the better answer blind, in
  shuffled order. A version that loses more than it wins is kept as `rejected` and never served.
  Among live versions, Thompson sampling over 👍/👎 decides the traffic. `saga evolve "<critique>"
  --user NAME` runs one evolution on demand.
* **Skills**: a successful multi-agent procedure is distilled into a recallable skill.

## Quick start

```bash
# Fedora
sudo dnf install cmake ninja-build gcc-c++ libcurl-devel libsodium-devel
# Debian/Ubuntu
sudo apt install cmake ninja-build g++ libcurl4-openssl-dev libsodium-dev pkg-config

cmake -S . -B build -G Ninja && cmake --build build

cp .env.example .env               # add your delegate key + account id from https://memory.walrus.xyz
./build/saga doctor                # health → whoami → remember → Walrus blob → recall
./build/saga serve                 # http://127.0.0.1:8080
```

Other commands:

```bash
./build/saga chat --user mira      # terminal chat (/good, /bad <why>)
./build/saga stats                 # memories + bytes per namespace (hackathon: ≥10 blobs)
./build/saga ab                    # before/after experiment → ab_report.md
./build/saga restore u:mira:facts  # rebuild the relayer index from Walrus
./build/saga serve --no-memory     # the "before" baseline
```

**Sign-in with Sui.** The app is gated by wallet sign-in: any Sui wallet in the browser (Wallet Standard —
Slush, Suiet, Phantom, …) signs a one-time challenge as a personal message, and your address becomes your
Saga identity, so your memory namespaces follow your wallet across devices. Ed25519 signatures are verified
in C++; every other scheme — including zkLogin accounts such as Slush's "Sign in with Google" — is verified
by a Sui full node (`verifySignature` over GraphQL). Sessions are stateless HMAC-signed cookies, so there is
still no database. Use `--no-auth` / `SAGA_AUTH=off` for single-user local runs.

**Bring your own accounts.** When Saga serves other people (`--host 0.0.0.0`, or `SAGA_ACCOUNTS=user`),
every user connects their *own* providers in **Agents**, and nothing runs on the operator's plans:

| Agent | How a user connects |
|---|---|
| `@saga` | nothing to connect: the default agent, DeepSeek V4 Flash on [Boundless](https://inference.boundless.network), on the operator's `BOUNDLESS_API_KEY` |
| `@claude` | paste a token from `claude setup-token` (Claude subscription) or an Anthropic API key |
| `@codex` | **Sign in with ChatGPT** (device code, shown in the browser) or an OpenAI API key |
| `@grok` | **Sign in with Grok** (device code) |
| ＋ | any OpenAI-compatible API with their own key (public addresses only: on a shared server Saga won't connect to loopback, private or link-local addresses on a user's behalf) |

**Credentials are sealed with the user's own vault key.** At sign-in the wallet signs a fixed "Unlock your
Saga vault" message; the browser hashes that signature into a 32-byte key and keeps it in a cookie. Tokens,
API keys and the Codex/Grok login files are stored on the server only as XSalsa20-Poly1305 ciphertext under
that key, which the server never writes down — so a copied disk or backup is useless, and a user's secrets
can only be opened during that user's own requests. Standard wallets sign deterministically, so the same
wallet recreates the key on any device; if a wallet can't (e.g. rotating-key Google wallets), Saga detects the
mismatch and asks the user to reconnect. **Disconnect deletes** the credential outright. See `/privacy`.

Each user's agents run inside a **bubblewrap sandbox**. The host filesystem is visible read-only, but the
operator's home, Saga's data, other users' homes and every key file are hidden. The user's own agent home
and chat workspace are the only writable places, and the environment is cleared, so the Walrus delegate key
never reaches an agent. Provider tokens reach the sandbox through its environment and prompts through stdin
or a 0600 file, never on a command line (which every local user can read with `ps`). Restoring checkpoints
never follows a link an agent left in the workspace. Provider logins live in the user's own home (mode 0700), sealed except while one of
that user's calls is running; none of them are written to Walrus memory. Reflection and prompt evolution
run on the user's own Claude account too. `bwrap` is required in this mode.

**Work on your GitHub repos.** Connect GitHub (fine-grained token, or "Sign in with GitHub" when
`SAGA_GITHUB_CLIENT_ID` points at an OAuth App with device flow), then pick a repo from the GitHub button
in the chat bar. Saga clones it into that chat's workspace — inside your sandbox — on branch
`saga/<chat>`, and every agent is told where it is and to commit there. **Open pull request** commits any
leftovers, pushes the branch and opens (or updates) the PR. The token is sealed in your vault and never
enters the agents' clone: everything in it (config, hooks, filters) is theirs to change, so the push runs
from a fresh blob-less clone of GitHub that fetches only the branch's new commits from the workspace, with
the token unset while it does. Agents can commit but cannot push, or see the token.

To deploy publicly, pass `--host 0.0.0.0` (per-user accounts are then the default). With operator
accounts (`SAGA_ACCOUNTS=host`), also set `SAGA_ACCESS_CODE` or `SAGA_ALLOWED_ADDRESSES`. Saga refuses to bind a public
interface without an access code, because the agents can edit files and run tools inside `workspaces/`.
Operator accounts are for people you trust: their agents run as you, **without a sandbox**, so they can read
the host's files (including `.env`) and each other's memory. Use per-user accounts for anyone else.

Each user can have up to 4 live tabs and 3 running chats at once; `SAGA_THREADS` (default 256) sets the
server's worker threads.

## Agents and LLMs

Agents are configured in `saga.json`:

| kind | backend | notes |
|---|---|---|
| `claude-code` | `claude -p --output-format stream-json` | the default *brain* (`--tools ""`) |
| `codex` | `codex exec --json -s workspace-write` | set `model` to one your plan allows |
| `grok-cli` | `grok -p --output-format streaming-messages-json` | |
| `openai` | `POST {base_url}/chat/completions` (streaming) | xAI, OpenRouter, Groq, Together, **Ollama / llama.cpp** |

If a teammate is out of quota, unauthenticated or unreachable, Saga hands its step to the primary agent
and shows the fallback in the UI. The user still gets a result.

**LLMs used in this submission:** Claude (via Claude Code) as the primary agent and brain, and OpenAI Codex
and xAI Grok as `@`-mentionable teammates. The relayer's fact extraction and embeddings run server-side
in MemWal.

## How the C++ MemWal client works

There is no official C++ SDK, so `src/memwal/` implements the relayer protocol directly with libsodium.
It was ported from the relayer source (`services/server/src/auth.rs`) and the Python SDK:

* **Signed requests**: Ed25519 over `{ts}.{METHOD}.{path}.{sha256(body)}.{nonce}.{account_id}`, sent as
  `x-public-key`, `x-signature`, `x-timestamp`, `x-nonce` (UUIDv4) and `x-account-id`.
* **SEAL session** (`x-seal-session`): a fresh Ed25519 session key and a Sui *PersonalMessage* signature
  (`blake2b256(0x03 0x00 0x00 ‖ uleb128(len) ‖ msg)`) over "Accessing keys of package … for 5 mins from …".
  The session key is encoded as a bech32 `suiprivkey`. It is cached until 30 s before expiry.
* Writes go through `/api/remember/bulk` (≤20 per call) on a background thread, which polls job status
  until Walrus returns a blob id. The UI shows each blob live, linked to Walruscan.

## Layout

```
src/core/      crypto (libsodium), http (libcurl), proc (subprocess streaming), .env
src/memwal/    relayer client + async Store (write queue, job tracking)
src/agents/    Claude Code / Codex / Grok CLI adapters, OpenAI-compatible adapter, registry
src/router/    @mention parsing (user messages + agent handoff lines)
src/harness/   context assembly, orchestration, reflection, prompt population
src/web/       cpp-httplib server (NDJSON chat stream, SSE write feed) + embedded single-page UI
```

## Honest limits

* Saga itself has no database. The hosted relayer keeps a vector index (in Postgres) over your encrypted
  Walrus blobs. `restore()` rebuilds it from Walrus, which is what makes Walrus the durable record.
* Relayer-managed decryption means the relayer sees plaintext while it serves a recall. That is the
  MemWal default mode. The manual (client-side SEAL) mode isn't implemented yet.
* All users of one deployment share one MemWal account and are isolated by namespace. Per-user
  accounts are future work.

## Research lineage

The harness design follows the reading list from **YC Paper Club: Harness Edition** (Aug 26, 2026),
compiled as DAIR.AI's [Harness Engineering collection](https://academy.dair.ai/papers/collections/harness-engineering):

* Yao et al., *ReAct* (2022): the interleaved act/observe loop each agent runs. [arXiv:2210.03629](https://arxiv.org/abs/2210.03629)
* Shinn et al., *Reflexion* (2023): verbal lessons from feedback, persisted here per agent. [arXiv:2303.11366](https://arxiv.org/abs/2303.11366)
* Wang et al., *Voyager* (2023): a skill library for reusable procedures. [arXiv:2305.16291](https://arxiv.org/abs/2305.16291)
* Packer et al., *MemGPT* (2023): memory as managed, tiered context. [arXiv:2310.08560](https://arxiv.org/abs/2310.08560)
* Talebirad & Nadiri, *Multi-Agent Collaboration* (2023): addressable agents with roles, here `@mentions`. [arXiv:2306.03314](https://arxiv.org/abs/2306.03314)
* Khattab et al., *DSPy* (2023) and Agrawal et al., *GEPA* (2025): the system prompt as an optimised artifact, evolved from failed traces. [arXiv:2310.03714](https://arxiv.org/abs/2310.03714), [arXiv:2507.19457](https://arxiv.org/abs/2507.19457)
* Zhang et al., *Agentic Context Engineering* (2025): an evolving playbook of rules with helpful/harmful counters, edited in small deltas to avoid context collapse. [arXiv:2510.04618](https://arxiv.org/abs/2510.04618)
* Zhang et al., *Darwin Gödel Machine* (2025): a self-modification is kept only after it is validated on real tasks. [arXiv:2505.22954](https://arxiv.org/abs/2505.22954)
* Lee et al., *Meta-Harness* (2026) and Karten et al., *Continual Harness* (2026): adapting the harness online around fixed weights. [arXiv:2603.28052](https://arxiv.org/abs/2603.28052), [arXiv:2605.09998](https://arxiv.org/abs/2605.09998)

## License

MIT
