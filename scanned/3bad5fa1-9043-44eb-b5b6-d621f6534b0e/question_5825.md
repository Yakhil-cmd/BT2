# Q5825: `SSH_ASKPASS` executes during git clone via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR author set `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` so that when `StackCommands#git_clone (git clone --recursive)` runs on the review-stack deploy host, the git subprocess names a program executed to answer ssh password prompts?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operations in Commands
- Attacker controls: `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the git subprocess in `StackCommands#git_clone (git clone --recursive)` inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: Git subprocesses spawned by Commands inherit no fork-controllable variable such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: set `SSH_ASKPASS` on the stack env, assert Command built for `StackCommands#git_clone (git clone --recursive)` passes it to the git subprocess.
