# Q0209: `NODE_OPTIONS` hijacks `yarn install` (node) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `yarn install` step, can an unprivileged fork PR author set `NODE_OPTIONS` through a `machine.environment` entry in the fork branch's `shipit.yml` so the node process injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `yarn install`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `NODE_OPTIONS` unfiltered into the `yarn install` subprocess, which injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: The `yarn install` subprocess inherits no fork-controllable environment key such as `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `yarn install` and injected `NODE_OPTIONS`, assert Command#unbundled_env passes `NODE_OPTIONS` to the spawned process.
