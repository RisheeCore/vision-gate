# VISION — Data Contracts & Repo Layout

## 1. Package Layout
vision/
├── vision/
│   ├── contracts.py
│   ├── cli.py
│   ├── events.py
│   ├── agent/      graph.py, state.py, nodes/__init__.py, routing.py, llm.py, prompts.py, driver.py
│   ├── policy/     engine.py, aliases.py, versions.yaml, rules/__init__.py
│   ├── sandbox/    runner.py, profiles.py, canary.py, Dockerfile
│   ├── redteam/    goals.py, mutators.py, attack_graph.py, split.py, validate.py
│   ├── eval/       policy_eval.py, humaneval.py, latency.py, stats.py, report.py
│   └── ui/         tui.py, plain.py, replay.py
└── tests/          sandbox/, policy/, agent/, redteam/, eval/
