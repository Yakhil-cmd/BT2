# Q5256: [prevent_with_label] `NODE_OPTIONS` in a `git` invocation in `StackCommands#fetch`/`#git_clone` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`prevent_with_label`, when the review stack runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can `NODE_OPTIONS` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the git subprocess inherits the merged env and honours attacker-set git variables and injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml` under `prevent_with_label`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `NODE_OPTIONS` injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: No fork-controllable key alters a `git` invocation in `StackCommands#fetch`/`#git_clone`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: inject `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `git` invocation in `StackCommands#fetch`/`#git_clone` process env.
