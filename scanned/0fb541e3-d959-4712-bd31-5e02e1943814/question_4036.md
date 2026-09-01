# Q4036: [allow_with_label] `RUBYLIB` in a `git` invocation in `StackCommands#fetch`/`#git_clone` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_with_label`, when the review stack runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can `RUBYLIB` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the git subprocess inherits the merged env and honours attacker-set git variables and prepends an attacker load path so `require` in a ruby step loads attacker code?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_with_label`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `RUBYLIB` prepends an attacker load path so `require` in a ruby step loads attacker code
- Invariant to test: No fork-controllable key alters a `git` invocation in `StackCommands#fetch`/`#git_clone`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: inject `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `git` invocation in `StackCommands#fetch`/`#git_clone` process env.
