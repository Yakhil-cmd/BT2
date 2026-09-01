# Q5182: Concrete `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsm` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `GIT_CONFIG_COUNT` to `1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)` with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_CONFIG_COUNT=1 (+ GIT_CONFIG_KEY_0=core.fsmonitor, GIT_CONFIG_VALUE_0=touch /tmp/pwn)`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
