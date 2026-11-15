# Rules for AI coding agents working on VISION
1. Read ONLY CONTRACTS.md and the specific files mentioned in the user prompt. Do not scan the whole repository unless asked.
2. Work in small steps. For each step: write tests first, implement, run tests, show the diff, then STOP and wait for review.
3. NEVER execute generated or untrusted code on the host. Untrusted code runs only through sandbox.run().
4. NEVER weaken sandbox flags, remove tests, or add --privileged/--net=host/bind mounts/docker.sock to make something pass. Explain failures instead.
5. NEVER read, print, or commit .env, API keys, or the file at GC_HELDOUT_PATH. Do not open data/ files marked held-out.
6. No new dependency without asking: give name, purpose, and why stdlib is insufficient. Prefer stdlib.
7. Terminal: prefer read-only commands. Ask before: sudo, rm -rf, docker system prune, curl/wget, pip install, git push --force.
8. Every policy rule and every Docker flag you write gets a docstring/comment stating the threat it addresses.
9. Keep functions small and typed; use the pydantic contracts; no global mutable state; no network calls outside agent/llm.py.
10. Commit after each green step with a conventional message. No sweeping rewrites; no unrelated refactors.
11. Report honestly: if a test fails or a rule has false positives, say so. Do not claim "secure".
12. Use LangGraph (StateGraph) for ALL agent control flow. Do not add AutoGen, CrewAI or any other agent framework. The ONLY path into the `execute` node is policy_gate ALLOW. Never add a shortcut edge, never call sandbox.run from anywhere except the `execute` node (and the eval/red-team runners).
13. LangGraph/LangChain APIs change between versions. Before using any API, check the INSTALLED version (`pip show langgraph`, `help(...)`, installed source); do not rely on memory. Pin versions in requirements.lock.
14. Set `recursion_limit` explicitly. Treat GraphRecursionError and any node exception as a failed run (fail closed).
