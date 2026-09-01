# Q2597: `GIT_EXEC_PATH` executes during fetch deployed revision via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR author set `GIT_EXEC_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml` so that when `StackCommands#fetch_deployed_revision` runs on the review-stack deploy host, the git subprocess redirects git subcommand resolution to an attacker directory?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `GIT_EXEC_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the git subprocess in `StackCommands#fetch_deployed_revision` inherits `GIT_EXEC_PATH` from Command#unbundled_env and redirects git subcommand resolution to an attacker directory
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `GIT_EXEC_PATH` on the stack env, assert Command built for `StackCommands#fetch_deployed_revision` passes it to the git subprocess.
