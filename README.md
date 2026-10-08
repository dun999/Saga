# Saga

**Agents working together with shared memory on Walrus mainnet.**

[![CI](https://github.com/dun999/Saga/actions/workflows/ci.yml/badge.svg)](https://github.com/dun999/Saga/actions/workflows/ci.yml)

Saga brings Claude Code, Codex, Grok, and OpenAI-compatible models into one conversation, with shared memory stored on **Walrus mainnet**. You assign work through `@mentions`; Saga supplies the context, passes results between agents, and saves what happened. Facts, decisions, corrections and handoff summaries go into one knowledge namespace for each user. Every teammate can use them.

> @claude build a landing page for my coffee cart, then @codex add a menu API, and @grok review both

Written in C++23 for the Walrus **“Chatbots That Remember”** hackathon, Saga applies ideas from **YC Paper Club: Harness Edition** and the research behind persistent memory and agent collaboration. See [Research lineage](#research-lineage) for the design influences.

**Try the live demo:** [usesaga.xyz/app](https://usesaga.xyz/app) has Walrus Memory configured on mainnet. **Run it locally:** [Try it](#try-it) explains how to build Saga, configure your own mainnet memory account, and verify that saved knowledge survives a new chat and a server restart.

## Why Saga exists

Working with several agents often means repeating the same context: what you are building, which tools you use, what went wrong last time, and how you want the work done. A useful correction in one conversation may never reach the next agent.

Saga gives that experience a shared home. Tell it that your project uses PostgreSQL, that you prefer short explanations, or that a previous deployment failed because a migration was missing. Those facts and lessons can be recalled when another agent picks up related work.

The **harness** is the software around the models: it decides what to remember, what context to retrieve, which agent should act, and how feedback affects the next attempt. In Saga, this layer owns the accumulated experience. You can change the model behind an agent while retaining the relevant history and shared knowledge.

## From a conversation to working software

A message can go to the default assistant or name several teammates. Saga turns mentions into an ordered sequence of tasks. Each agent receives the relevant memories, the conversation, and the results of earlier steps. Agents can also hand work to another teammate.

For the coffee-cart example, Claude can build the page, Codex can use that work to add the menu API, and Grok can review the combined result. A shared task record captures what each agent did. The conversation and a compact episode summary become memory for later sessions.

The browser UI brings the workflow together:

- **Chat with multiple agents.** Mention teammates, see their progress, and inspect recalled memories.
- **Connect your providers.** Use Claude, Codex, Grok, or an OpenAI-compatible endpoint with your own account.
- **See what they built.** When agents leave a page (`index.html`) in the chat's workspace, a live preview opens beside the chat. It runs in a sandboxed origin, so the page's scripts can't see your session.
- **Work on a repository.** Connect GitHub, select a repo, and let coding agents work in a chat workspace. Open a pull request from the resulting changes.
- **Give feedback.** Explain what went wrong so every teammate can recall the correction.
- **See memory being saved.** Pending writes become links to Walrus blobs when storage is confirmed.
- **Clear chat history without losing memory.** Delete a chat from the sidebar; saved facts, corrections and lessons remain available to your agents.

Saga also provides terminal chat. Sui wallet sign-in, or a username with a password, gives browser users an identity across devices within a deployment; local guest usernames support trying it on your own machine.

## How the harness works

```mermaid
flowchart TD
    U[Your message and mentions] --> R[Recall shared knowledge]
    W[(Walrus mainnet)] --> R
    R --> C[Fixed foundation plus relevant context]
    C --> A[Run agents in order with shared files and prior results]
    A --> O[Answer and workspace changes]
    A --> K[Propose useful facts and decisions]
    K --> Q[Queue shared memory and expose it to the next agent]
    O --> M[Save transcript, handoff summary and checkpoints]
    O --> F[Your explicit correction]
    F --> Q
    Q --> W
    M --> W
```

The checked-in [saga.json](saga.json) defines the team. The **primary agent** answers unmentioned requests; there is no separate learning agent.

| Agent | Backend | Role in the default configuration |
|---|---|---|
| `@saga` | Boundless inference, model `dsv4` | Primary chat assistant |
| `@claude` | Claude Code | Coding and workspace changes |
| `@codex` | Codex CLI | Coding and workspace changes |
| `@grok` | Grok CLI | Coding and workspace changes |

The OpenAI-compatible adapter supports streaming chat responses. Workspace editing and command execution come from the CLI agents. Additional API agents can be configured in `saga.json` or connected through the UI. If a teammate encounters a recognized quota, authentication, or connectivity failure, Saga attempts a fallback to the primary agent and shows the change.

## What Saga remembers

All reusable knowledge is written to **`u:<user>:shared`**. A record retains its type, author and session, so another agent can use it with context.

| Record type | What it contributes |
|---|---|
| **Fact or decision** | Project context, preferences and verified decisions |
| **Correction** | Explicit user feedback about an earlier request |
| **Episode** | A compact account of what the team attempted and completed |
| **Lesson or skill** | Guidance and procedures preserved from older memory |

The store validates and queues new knowledge through one capture path. Within the running process, normalized content IDs avoid writing the same proposal twice. A bounded cache shares recent proposals immediately, including with the next teammate before Walrus confirms them. These local entries have a storage status and no fabricated blob ID or retrieval distance. They are durable only after confirmation.

Saved transcripts, file checkpoints and user settings keep separate archive namespaces (`u:<user>:chat`, `:checkpoints`, `:settings`). They are searched or restored separately, rather than competing with knowledge during ordinary recall.

The trash button beside a chat removes it from your history on this Saga server, across browsers and restarts. It keeps shared memory, workspace files, checkpoints and archived Walrus transcripts. Deletion markers live in `~/.config/saga/deleted-chats/`; include that directory when moving or backing up the server to keep deleted chats hidden. This action does not erase stored Walrus blobs.

Older facts, episodes, skills and per-agent lessons are included automatically in shared recall. Saga discovers their namespaces through the relayer inventory, with a fallback to known namespaces on older relayers. Their original blob IDs and namespaces remain intact; no copy or destructive migration is required. Historical prompt populations and learning scores are no longer loaded or changed.

### Why Walrus

Saga stores durable memory as encrypted blobs through [Walrus Memory (MemWal)](https://github.com/MystenLabs/MemWal). MemWal supplies fact extraction, embeddings, semantic retrieval, and access to the stored blobs. The relayer's search index can be rebuilt from Walrus, so confirmed memories can outlive the Saga process and be recovered by a deployment with the appropriate account credentials.

The C++ client in [src/memwal](src/memwal) implements signed relayer requests, SEAL sessions, and asynchronous writes. The UI exposes storage progress and the resulting blob IDs, making the memory layer visible during a conversation.

A turn starts one shared-knowledge search alongside settings and conversation-history reads. Every teammate receives the same result; recent proposals are added before each step. Existing users may need additional reads for their legacy namespaces. Writes happen in the background and are batched, so an answer can arrive before its memories finish saving.

The relayer limits each delegate key to 60 weighted requests a minute (recalls and status checks count 1, a write 5, a batch of writes 10). Saga tracks that budget itself: background work (writes, status checks, index restores) waits for headroom and leaves a reserve, so a user's reads are not refused with a minute-long `Retry-After` because of writes that could have been spaced out. Connections to the relayer are reused, which saves a TLS handshake (100–400 ms) on every call.

Saga has no application database, but it does keep local workspaces, agent homes, chat deletion markers, and optionally encrypted provider credentials.

Agents use the same memory. In host account mode, Claude Code gets `memory_recall` and `memory_remember` from `saga mcp`, while other CLI agents use `saga mem` from their shell. In user account mode, sandboxed CLI agents can also search saved transcripts and other memory on demand: Claude gets the read-only `memory_recall` tool, and Grok and Codex use `saga mem recall`. A per-run socket permits at most eight searches of the current user's content namespaces, rejects other users and direct writes, and keeps the delegate key on the server. New facts are proposed with `#remember`. Claude Code's own auto-memory and claude.ai connectors are switched off in Saga runs.

Saved transcripts retain up to 4,000 bytes of each user message and 6,000 bytes of each agent response, after redaction; longer entries carry truncation flags. Failed steps retain their partial response and error separately. Checkpoints save only eligible text files within their size budget. Restore skips a file whose newest checkpoint has no saved content, rather than overwriting it with an older version.

Sandboxed Claude runs preapprove shell tools in the default `acceptEdits` mode because Saga has no interactive permission responder; explicit modes such as `plan` remain in effect. Agent memory budgets respect the tightest ancestor cgroup limit and leave at least one quarter for Saga itself. On the 8 GB deployment, the service has a 6 GiB cap, agents share up to 4 GiB, and each run is capped at 2 GiB. Each run allows 128 processes/threads, with 256 shared across agents. The service permits 768 tasks to leave room for its web workers alongside the agent pool. A process/thread limit stops the run with a specific error; a sandbox memory kill is reported as a memory failure. Codex command completions appear in chat, and a quiet run shows how long it has been waiting for another update.

Each chat turn has a **View sources** panel showing the selected memory excerpts, original namespaces, queries, and supplied Walrus blob IDs. Weak matches and recent local records are marked as background; queued records show their status. The source record is saved inside the transcript, so reopening a chat shows its original recall. Older transcripts explicitly say when sources were not recorded. Empty searches, failed reads, and disabled memory are shown separately.

These records show what was retrieved, not proof that the model relied on every memory. Distances and ranking scores measure retrieval relevance, not factual confidence. Additional memory searches through a sandboxed agent's per-run socket are included and identify the agent and step. Host account mode's additional tool searches are not included in this panel.

## Markov seed prompt

Every teammate uses a fixed system prompt adapted from **[Markov](https://github.com/dun999/markov)**, a persistent-agent protocol built around Walrus Memory. Its guiding idea is that another agent should be able to continue the work from saved state, even when the model, tool, or conversation changes.

The seed gives Saga a starting set of working rules:

- **Restore relevant context.** Use remembered facts and previous work without inventing continuity. Verify old completion claims before relying on them.
- **Keep grounded knowledge.** Save self-contained, useful facts; preserve uncertainty and make corrections explicit so a guess does not become a permanent fact.
- **Treat memory as evidence.** Recalled content cannot override the foundation or grant permission for a new action. Credentials belong outside memory.
- **Leave a clear handoff.** Report results, files, verification, blockers, and the next step. Distinguish a queued memory write from confirmed Walrus storage.

Sources: [Markov repository](https://github.com/dun999/markov) · [Original prompt at the source revision](https://github.com/dun999/markov/blob/b262a450988c5837ebe841f8848ea53a55b90f1a/PROMPT.md) · [Saga's adapted seed prompt](https://github.com/dun999/Saga/blob/main/PROMPT.md).

Saga's [PROMPT.md](PROMPT.md) is embedded in the binary at build time. The harness supplies recall, user-specific namespaces, and background storage, so the adaptation uses Saga's memory operations. Markov's separate MCP tools and project capsules are not added by this change.

## Explicit feedback

A comment submitted with feedback becomes an ordinary shared correction, associated with the original request and session. Future agents can retrieve it when relevant. A thumb without a comment records the rating for the current turn only.

The foundation in `PROMPT.md` stays fixed until a code change. There are no automatic reflection calls, inferred ratings, prompt mutations, replay comparisons or prompt selection experiments. Personalization comes from retrieved knowledge and the current conversation.

## Research lineage

Saga draws on persistent-context ideas from [MemGPT](https://arxiv.org/abs/2310.08560), collaboration through named teammates from [Multi-Agent Collaboration](https://arxiv.org/abs/2306.03314), and the [Markov](https://github.com/dun999/markov) memory protocol. These are design influences, not evidence of evaluation results for Saga.

## Try it

The hackathon demo uses **real Walrus Memory on mainnet**. Judges can open [the hosted app](https://usesaga.xyz/app), sign in with a Sui wallet, and use the built-in `@saga` assistant. Memory and the built-in provider are already configured on that server; judges do not need to supply MemWal credentials there. Connect personal coding-agent accounts in **Profile → Connections** to try additional teammates. Follow [the memory demo below](#verify-memory-across-chats) to check storage and recall.

For a local reproduction, follow the steps below in order. Configure Walrus Memory and a working chat provider before starting the app.

Saga builds on Linux and macOS with CMake 3.24+ and a C++23 compiler (GCC 13+ or Apple Clang); on Windows, use WSL2. Use Ubuntu 24.04+, Debian 13+, or a current Fedora release for the packages below. Older distributions may supply a compiler or CMake that is too old. The first build downloads pinned dependencies from GitHub, so it needs internet access. Python 3 runs the local smoke check.

| Requirement | What you need |
|---|---|
| Build Saga | The toolchain and packages below |
| Save and recall Walrus memory | A mainnet MemWal account and its registered delegate private key: `MEMWAL_ACCOUNT_ID` and `MEMWAL_PRIVATE_KEY` |
| Chat with the default `@saga` assistant | `BOUNDLESS_API_KEY` |
| Chat with `@claude`, `@codex` or `@grok` | That CLI installed and signed in locally; mention the agent explicitly |

Walrus Memory is required for this walkthrough. Choose at least one chat provider; you do not need all three coding CLIs.

Install the dependencies for your system:

```bash
# Fedora
sudo dnf install cmake ninja-build gcc-c++ binutils libcurl-devel libsodium-devel zlib-devel git pkgconf curl python3

# Debian / Ubuntu (including Ubuntu on WSL2)
sudo apt update
sudo apt install cmake ninja-build g++ binutils libcurl4-openssl-dev libsodium-dev zlib1g-dev git pkg-config curl python3

# macOS, with Homebrew (curl and zlib come with the system)
brew install cmake ninja libsodium pkgconf python
```

On **Windows**, install WSL2 with Ubuntu (`wsl --install` in PowerShell), open the Ubuntu terminal, and follow the Debian / Ubuntu steps there. Install and sign in to the `claude`, `codex`, and `grok` CLIs inside Ubuntu as well, since Saga runs them from there. Open the UI from your Windows browser at the same `http://127.0.0.1:8080`.

Everything below runs the same on Linux, macOS, and WSL2. The one exception is serving other people (`--accounts user`): its agent sandbox needs Linux (bubblewrap, seccomp, and cgroup v2).

Clone the public repository and stay in its root for the following commands:

```bash
git clone https://github.com/dun999/Saga.git
cd Saga
```

On Linux, the compiler and assembler need to come from the same toolchain. GCC 15 and newer emit a `.base64` assembler directive, and binutils older than 2.43 reject it with `unknown pseudo-op: .base64`. If `command -v as` selects an old custom installation, put the distro binaries first before configuring:

```bash
export PATH=/usr/bin:$PATH
```

This keeps the rest of your `PATH`, so the `claude`, `codex`, and `grok` CLIs, often in `~/.local/bin`, stay available to Saga. If you already attempted a build, use `cmake --fresh -S . -B build -G Ninja` to reset its CMake cache, then build again.

From the repository root:

```bash
cmake -S . -B build -G Ninja
cmake --build build --parallel 2
./build/saga help
```

Two compile jobs limit memory use on laptops; use `--parallel 1` if a compiler process is killed.

### Configure mainnet memory and a provider

1. Open the [Walrus Memory dashboard](https://memory.walrus.xyz/dashboard), connect your Sui wallet, and create or select your **mainnet** MemWal account.
2. Create a delegate key for Saga and keep its **private key**. Saga accepts a `suiprivkey1...` key or a 64-character hexadecimal Ed25519 seed. The delegate public key used as `MEMWAL_AGENT_ID` in the submission form is a different value.
3. Copy the **MemWalAccount object ID** into `MEMWAL_ACCOUNT_ID`. This is the account's `0x...` object ID, distinct from the wallet address. The key must be registered to this account.
4. Create `.env` only if it does not already exist, then edit it locally. Keep existing credentials and `saga.json` settings.

```bash
test -e .env || cp .env.example .env
```

Replace the placeholders with your own values:

```dotenv
MEMWAL_PRIVATE_KEY=suiprivkey1...
MEMWAL_ACCOUNT_ID=0x...
BOUNDLESS_API_KEY=...
```

Get `BOUNDLESS_API_KEY` from [Boundless inference](https://inference.boundless.network) to use the default `@saga` assistant. Alternatively, install and authenticate a coding CLI and use its `@claude`, `@codex`, or `@grok` mention. The two MemWal values are required in either case. A message without a mention goes to `@saga` and needs its Boundless key.

Keep each value alone on its line: a trailing `# comment` becomes part of the key. Environment variables take precedence over `.env`, including already-exported empty values. Private keys stay local and must not be committed. The default relayer is the [production mainnet endpoint](https://github.com/MystenLabs/MemWal/blob/dev/docs/getting-started/quick-start.md), `https://relayer.memory.walrus.xyz`. If `MEMWAL_SERVER_URL` is already set, check that it points to a mainnet relayer.

### Verify Walrus, then start Saga

```bash
./build/saga doctor
```

`doctor` checks the relayer, reports the network and account, writes a real probe, waits for its Walrus blob, and recalls it. Continue only when the network is **mainnet**, the relayer/account/write/recall checks say **ok**, and the command exits successfully with a Walruscan blob link. Agent availability lines are separate: unused CLI agents can be unavailable, but your chosen provider must be ready for chat.

Missing MemWal values produce `MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID must be set (see .env.example)`. Fix the credentials before continuing. For write or recall failures, check the delegate/account pairing, mainnet relayer, and reported error; a pending or failed write is not confirmed storage.

```bash
./build/saga serve
```

Open **http://127.0.0.1:8080/app**. Choose a guest name such as `judge-demo` and press **Continue as guest**. Keep this identity for the following test; its knowledge is stored in `u:judge-demo:shared`. In your profile's **Account** tab, check that Memory is **On** under **Walrus memory**. If port 8080 is taken, use `./build/saga serve --port 8081` and open that port instead.

### Verify memory across chats

Use a unique project name for each attempt, such as `HarborCart-<unique-suffix>`:

1. Ask a configured agent: `@saga Remember this project decision: HarborCart-<unique-suffix> uses PostgreSQL for its database. Save it as shared memory.` If using a CLI provider, replace `@saga` with its mention.
2. Open **Memory → Shared knowledge** and **Walrus writes**. Wait for the project fact to appear with a confirmed blob ID and a Walruscan link. A queued proposal alone does not establish persistence.
3. Start a **new chat** under the same guest name or wallet. Ask `What database did we choose for HarborCart-<unique-suffix>?` without repeating the answer. Mention another connected teammate to check shared recall between agents.
4. Open **View sources** on that new turn. Check that the earlier project fact was retrieved with its Walrus blob ID, then check the answer. This makes the stored evidence visible alongside the model's response.
5. For a local durability check, stop Saga with Ctrl+C after writes confirm, restart `./build/saga serve`, and repeat step 3 in a new chat under the same identity. This clears the running process's recent-memory cache while retaining the confirmed Walrus records.

You can also verify the local user's memory from a separate terminal process:

```bash
./build/saga mem recall "What database does HarborCart-<unique-suffix> use?" --ns u:judge-demo:shared
```

Use the same project suffix and local guest name as above. The output should include the saved fact and its blob ID. On the hosted app, your identity is your wallet address; use the app's source panel to inspect its memory.

### Terminal chat and build checks

Terminal chat also uses Walrus Memory:

```bash
./build/saga chat --user judge-demo
```

Mention your configured provider. `/quit` exits; `/good` and `/bad <reason>` rate the last turn, and a feedback comment is queued as shared knowledge. Start the command again with the same user to test recall in a new session. `./build/saga serve --trace` shows recall and agent phases; `./build/saga help` lists the commands.

The automated checks are useful for code changes:

```bash
ctest --test-dir build --output-on-failure
python3 tests/local/smoke.py ./build/saga
```

These checks use local fixtures and isolate credentials. They verify the build and application behavior; the real mainnet proof is `doctor` and the memory demo above. CI runs the build and these checks on Fedora, Ubuntu 24.04 and macOS.

The same mainnet setup, written as a sequence an agent can follow, is in [llms.txt](llms.txt). The server also returns that file at `/llms.txt`. Agent configuration lives in [saga.json](saga.json), and environment variables are listed in [.env.example](.env.example).

Local serving defaults to the operator's accounts and runs CLI agents without Saga's sandbox. For a shared deployment, Saga supports wallet-only sign-in, user-owned provider accounts, encrypted credential storage, and bubblewrap isolation. Public serving requires `--accounts user --public-origin https://your.host --agent-cgroups PATH`. Every request then needs a signed-in session: a Sui wallet, or a username with a password (the first sign-in claims the name; a name that already has memory can't be claimed). Add `--wallet-only` to allow wallets alone. See [deploy/saga.service](deploy/saga.service) for the Linux service configuration and [deploy/saga.caddy](deploy/saga.caddy) for the reverse proxy; it requires systemd 254+, kernel 5.14+, bubblewrap 0.9+, delegated cgroup v2 controls, and separately configured filesystem quotas.

## Current boundaries

MemWal's default relayer-managed decryption exposes recalled plaintext to the relayer. Users of a deployment share one MemWal account with namespace separation; per-user relayer accounts and client-side SEAL decryption are not implemented.

Relayer latency affects chat because recall happens before the answer (each recall takes one to two seconds; a turn's reads run in parallel). Every user of a deployment shares one delegate key's budget of 60 weighted requests a minute; a busy deployment confirms writes more slowly before it lets reads fail. Failed reads can leave an agent with less memory context, and queued writes are durable only after confirmation. File checkpoints are partial snapshots, with content capped at 16,000 bytes per file and 40,000 bytes per step.

Chat-history listing and restoration currently inspect at most 100 recent archive records. The in-process knowledge cache is bounded to 256 recent writes across the deployment and disappears on restart; confirmed Walrus records remain retrievable.

## Code map

| Directory | Responsibility |
|---|---|
| [src/harness](src/harness) | Context assembly, orchestration, shared knowledge and archives |
| [src/memwal](src/memwal) | Relayer protocol, memory writes, retrieval, and secret redaction |
| [src/agents](src/agents) | CLI and OpenAI-compatible adapters |
| [src/router](src/router) | Mention parsing and handoffs |
| [src/core](src/core) | Cryptography, HTTP, subprocesses, sandboxes, and credentials |
| [src/github](src/github) | Repository and pull request workflow |
| [src/web](src/web) | Server, wallet authentication, and embedded UI |
| [tests](tests) | Shared-memory regressions and a credential-free local smoke check; optional sandbox tests |

## License

[MIT](LICENSE)
