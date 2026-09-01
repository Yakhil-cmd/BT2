# Q0226: `GIT_CONFIG_COUNT` executes during git checkout via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR author set `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml` so that when `TaskCommands#checkout (git checkout)` runs on the review-stack deploy host, the git subprocess with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_CONFIG_COUNT` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the git subprocess in `TaskCommands#checkout (git checkout)` inherits `GIT_CONFIG_COUNT` from Command#unbundled_env and with GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 injects `core.fsmonitor`/`core.hooksPath`/`alias` that git runs as a command
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_CONFIG_COUNT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_CONFIG_COUNT` on the stack env, assert Command built for `TaskCommands#checkout (git checkout)` passes it to the git subprocess.
