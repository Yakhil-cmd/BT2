# Q4167: Concrete `PATH=/tmp/attacker-bin:$PATH` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `PATH` to `/tmp/attacker-bin:$PATH` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `PATH=/tmp/attacker-bin:$PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `/tmp/attacker-bin:$PATH` prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary
- Invariant to test: No spawned deploy process ever sees a fork-controlled `PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `PATH=/tmp/attacker-bin:$PATH`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
