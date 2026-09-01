# Q2222: [allow_with_label] `GIT_TEMPLATE_DIR` during git clone local via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR set `GIT_TEMPLATE_DIR` via a `machine.environment` entry in the fork branch's `shipit.yml` so `TaskCommands#clone (git clone --local)` executes attacker code, given the git subprocess supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: lib/shipit/stack_commands.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> git operation in Commands
- Attacker controls: `GIT_TEMPLATE_DIR` via a `machine.environment` entry in the fork branch's `shipit.yml`, git op `TaskCommands#clone (git clone --local)` under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `TaskCommands#clone (git clone --local)` inherits `GIT_TEMPLATE_DIR` and supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: Git subprocesses inherit no fork-controllable variable such as `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: set `GIT_TEMPLATE_DIR` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the Command for `TaskCommands#clone (git clone --local)` passes it to git.
