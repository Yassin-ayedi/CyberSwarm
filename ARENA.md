# CyberSwarm Arena (MVP, branch `mvp-coevolution`)

Goal: train a **defender that handles attacks it has never seen**, by playing against an
attacker that also improves. The original purple-team pipeline (`orchestrator/main.py`,
`config/*.yaml` except `arena.yaml`) is untouched and still runs.

## What changed compared to the original project

| Problem in the original | What the arena does instead |
|---|---|
| Red followed a 6-step recipe with exact payloads | Red only gets a goal, its tools and its network; it must discover targets and exploits itself |
| Blue was told the attacker's IP pattern and the legit user's IP | Blue gets a way of working (observe, hypothesise, act, verify) and no answers |
| Blue played after Red had finished, so blocking changed nothing | **Game clock**: every tick Red may act, then Blue reads the sensors and may act. A block stops Red immediately |
| Blue was told when the attack happened | The attack starts at a **random tick**; Red acts at random ticks; 20% of episodes have **no attack** (false-alarm training) |
| Same IPs every round (Blue could memorise them) | Attacker and customer get **random IPs** every episode |
| `patch_sqli` did nothing; only one real action | Blue tools: `inspect_ip`, `raise_alert`, `block_ip`, `rate_limit`, `unblock_ip`, `add_ids_rule`, `wait` |
| Blue saw only signature alerts | Blue also sees behaviour per source: request volume, HTTP status codes, paths, ports |
| Scores rewarded calling tools | Scores come from ground truth: time to detect/contain, damage (Juice Shop solves, flag), false alarms, customer availability |
| Train and test were the same situation | Held-out test: 4 **scripted attacks** Blue never trains on (brute force, slow scan, sqlmap, directory busting), on different seeds |
| Only the terminal | Web dashboard: live network map, tick timeline, scoreboard, learning curves, trained-vs-untrained comparison |

### Added for mvp2

- **Attacker can move (`change_ip`, 3 per episode)**: like switching proxy or VPN exit. A block on its
  old address no longer applies, so the defender must recognise the same behaviour coming from a
  new address. The spare addresses come from the scenario seed, so trained and untrained defenders
  face identical moves. Scripted test attacks move automatically after 2 blocked steps in a row.
- **Defender WAF (`block_pattern` / `unblock_pattern`)**: blocks requests by content, whoever sends
  them (a small proxy on the gateway, only switched on when the first pattern is added).
- **Clear attacker outcomes**: answered / blocked by the defender / rate-limited / rejected by the
  WAF / nothing there or failed / refused by the lab rules (out of scope).
- **Range scans** (`10.10.2.0/24`) and 2 attacker actions per turn; 18 ticks per episode.
- **Fully independent episodes**: Flask + database recreated and the attacker box cleaned each episode;
  connections from the previous episode are ignored by the sensors.
- **Early end**: once the attacker has no address change left and its last 2 actions hit the block.
- New scores: address changes, re-blocked after a change, shut out at the end, exposure ticks
  (ticks the attacker could act with its current address unblocked, 1 point of penalty each).

## How one episode works

```
tick:   0    1    2    3    4    5    6    7   ...  13
legit:  ███  ███  ███  ███  ███  ███  ███  ███       ███   customer browses all the time
red:    ·    ·    ·    ATK  ·    ATK  ATK  ·         ATK   starts at a random tick
blue:   👁   👁   👁   👁   👁⚡ 👁   ...                   reads sensors every tick, acts when it decides
```
Per tick: (1) Red acts if scheduled, (2) sensors are read (Suricata alerts + HTTP/flow
behaviour since the last tick), (3) Blue may make up to 3 calls, (4) ground truth is recorded
(firewall state, customer success) but never shown to Blue.

After each training episode both sides **reflect**: they get the episode report (with the
ground truth that was hidden during play, IPs replaced by `<attacker>`/`<customer>`) and write
1-3 lessons to their playbook. The playbook goes into their prompt next episode. Every prompt
and answer is also saved (`ep_XXX_exchanges.jsonl`) for a later fine-tuning step.

## Scores

Blue reward (attack episode) = +10 detected, +10 contained, minus 1 per tick to contain,
minus 5 per Juice Shop challenge Red solved, minus 10 if Red got the flag, minus 3 per action
against an innocent IP, minus 10 if the customer was blocked, minus 10 x (1 - availability).
Quiet episode: +10 if Blue did nothing wrong, with the same penalties.

Red reward = 5 per challenge solved + 10 for the flag + 0.5 per request that got an answer,
minus 5 if contained.

## Run it

Prerequisites, in this order:
1. Docker Desktop running, then `cd lab; docker compose up -d --build`
2. **Then** `powershell -File lab/setup.ps1` (after the networks exist; Docker Desktop turns
   its bridge filter back on when it creates them). The arena refuses to start if it is on.
3. SSH tunnel to the GPU VM's Ollama on `localhost:11434` (model `qwen2.5:14b`).

```powershell
cd orchestrator
python arena_main.py train --run mvp1 --episodes 8
python arena_main.py eval  --run mvp1 --attackers scripted --episodes 8
python arena_main.py eval  --run mvp1 --attackers scripted --episodes 8 --untrained
```
Add `--fake` to any command to run without Docker or GPU (simulated lab, rule-based fake
model; for testing the pipeline only, its numbers mean nothing).

Console (dashboard + experiment manager): `python dashboard/server.py`, then open
<http://localhost:8000/dashboard/>. From the **Experiments** page you can start a new
experiment (training + held-out test + optional untrained baseline) and stop it; every page
follows a running episode live. The SSH tunnel must be up before starting an experiment.

## Files

| File | Role |
|---|---|
| `orchestrator/arena_main.py` | command line: train / eval |
| `orchestrator/arena/match.py` | game clock, scoring, reflection |
| `orchestrator/arena/scenario.py` | random scenarios (IPs, start tick, quiet episodes, attacker type) |
| `orchestrator/arena/prompts.py` | goal-only Red prompt, method-only Blue prompt, reflection prompts |
| `orchestrator/arena/tools.py` | tool schemas for both sides |
| `orchestrator/arena/lab.py` | real Docker lab backend (tools, IP randomisation, ground truth) |
| `orchestrator/arena/sensors.py` | incremental Suricata reader and the digest Blue reads |
| `orchestrator/arena/attackers.py` | held-out scripted attacks |
| `orchestrator/arena/agents.py` | per-tick LLM agent with short memory |
| `orchestrator/arena/fakelab.py`, `fakellm.py` | dry-run simulator |
| `orchestrator/arena/smoke_live.py` | checks each lab piece on the live lab |
| `dashboard/index.html` | web dashboard |
| `config/arena.yaml` | models, ticks, probabilities, seeds |

Lab changes: the gateway image now has `curl` (the referee reads the Juice Shop scoreboard
from the gateway, which Blue cannot block), and Suricata logs extended HTTP fields (method and
status code).

## Limits of this MVP (next steps)

- Learning is prompt-level (playbooks). Fine-tuning on the saved exchanges is the next step.
- One target app, one customer, a 14B model; small numbers of episodes, so results are
  indicative. Run more episodes and seeds for real claims.
- Red plays against a single Blue, not a pool of past versions.
