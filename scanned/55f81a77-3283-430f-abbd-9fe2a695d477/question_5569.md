# Q5569: `GIT_CONFIG_GLOBAL` executes during git fetch sha via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR author set `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml` so that when `StackCommands#fetch_commit (git fetch <sha>)` runs on the review-stack deploy host, the git subprocess supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the git subprocess in `StackCommands#fetch_commit (git fetch <sha>)` inherits `GIT_CONFIG_GLOBAL` from Command#unbundled_env and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_CONFIG_GLOBAL` on the stack env, assert Command built for `StackCommands#fetch_commit (git fetch <sha>)` passes it to the git subprocess.
