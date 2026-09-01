# Q2212: Concrete `GIT_ASKPASS=/tmp/evil.sh` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `GIT_ASKPASS` to `/tmp/evil.sh` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_ASKPASS=/tmp/evil.sh` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `/tmp/evil.sh` points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_ASKPASS=/tmp/evil.sh`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
