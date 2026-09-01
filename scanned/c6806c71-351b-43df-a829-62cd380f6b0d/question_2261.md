# Q2261: Concrete `NODE_OPTIONS=--experimental-loader file:///` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `NODE_OPTIONS` to `--experimental-loader file:///tmp/e.mjs` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `NODE_OPTIONS=--experimental-loader file:///tmp/e.mjs` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `--experimental-loader file:///tmp/e.mjs` injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: No spawned deploy process ever sees a fork-controlled `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `NODE_OPTIONS=--experimental-loader file:///tmp/e.mjs`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
