"""
Scenario generator. Every episode is different, so Blue cannot memorise an answer:
  - the attacker and the legitimate user get random IPs on the client network,
  - the attacker also gets a few spare addresses it can move to (change_ip) when blocked,
  - the attack (if any) starts at a random tick and Red acts at random ticks after that,
  - some episodes contain no attack at all (Blue must stay calm),
  - the attacker is either the LLM Red (training) or a scripted attack (held-out tests).
The same seed always gives the same scenario (spare addresses included), so an episode can
be replayed and the trained and untrained defenders face exactly the same situations.
"""
import random
from dataclasses import dataclass, asdict, field

SCRIPTED = ["bruteforce_login", "slow_scan", "sqlmap_search", "dir_bust"]
MAX_IP_CHANGES = 3


@dataclass
class Scenario:
    seed: int
    n_ticks: int
    attack: bool
    attacker: str          # "llm" or one of SCRIPTED
    attacker_ip: str       # starting address
    legit_ip: str
    red_start_tick: int
    red_ticks: list        # ticks at which Red acts
    spare_ips: list = field(default_factory=list)   # addresses change_ip moves to, in order

    def to_dict(self):
        return asdict(self)


def make(seed, n_ticks=14, attacker="llm", quiet_prob=0.2, act_prob=0.75, ip_changes=MAX_IP_CHANGES):
    rng = random.Random(seed)
    hosts = rng.sample([h for h in range(30, 240) if h != 50], 2 + ip_changes)   # .50 = red-box primary
    attacker_ip, legit_ip = f"10.10.1.{hosts[0]}", f"10.10.1.{hosts[1]}"
    spare = [f"10.10.1.{h}" for h in hosts[2:]]
    attack = rng.random() >= quiet_prob
    start = rng.randint(2, max(2, n_ticks // 2 - 1))
    red_ticks = []
    if attack:
        red_ticks = [start] + [t for t in range(start + 1, n_ticks) if rng.random() < act_prob]
    return Scenario(seed=seed, n_ticks=n_ticks, attack=attack, attacker=attacker if attack else "none",
                    attacker_ip=attacker_ip, legit_ip=legit_ip,
                    red_start_tick=start if attack else -1, red_ticks=red_ticks,
                    spare_ips=spare if attack else [])
