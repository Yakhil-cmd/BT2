### Title
`EnvironmentVariables#interpolate` falls back to raw process `ENV` when a `$VAR` reference is not in the whitelisted stack/task env, bypassing `deploy.variables`/`rollback.variables` whitelisting - (File: `lib/shipit/environment_variables.rb`)

### Summary
`EnvironmentVariables#interpolate` (lib/shipit/environment_variables.rb:20-27) is the only mechanism by which `$VAR` references inside a `shipit.yml` step are substituted, since `Command#start` invokes `PTY.spawn` with an argv array rather than through a shell (lib/shipit/command.rb:92). When the referenced variable is absent from the whitelisted env hash passed into `Command`, `interpolate` silently falls back to the Shipit host process's own `ENV`, defeating the whitelist that `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` (app/models/shipit/deploy_spec.rb:174-180) are meant to enforce.

### Finding Description
The broken binding: the set of variables a step can reference should equal `deploy_variables`/`rollback_variables` declared in `shipit.yml` (as enforced by `EnvironmentVariables#permit`, lib/shipit/environment_variables.rb:13-18), i.e. `interpolatable_vars == whitelist`. Instead, `interpolate` computes `@env.fetch(variable) { ENV[variable] }` (lib/shipit/environment_variables.rb:25), so `interpolatable_vars == whitelist ∪ Shipit_process_ENV`.

Code path: a step string coming from `DeploySpec#deploy_steps`/`rollback_steps` (attacker-controlled via the PR's `shipit.yml`) is wrapped into a `Command` (lib/shipit/task_commands.rb:19,25) with some `env` hash. `Command#interpolated_arguments` → `interpolate_environment_variables` → `EnvironmentVariables.with(env).interpolate(argument)` (lib/shipit/command.rb:51-55, 81-83). If the step references `$SOME_SECRET` and `SOME_SECRET` is not a key in the `env` hash handed to `Command` (i.e., not declared under `deploy.variables`/`rollback.variables` and not already part of `@stack.env`/`@task.env`), the `fetch` block executes and returns `ENV['SOME_SECRET']` — the Shipit web/worker process's own environment variable — which is then Shellwords-escaped and placed directly into `argv` for `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` (lib/shipit/command.rb:92).

Because steps never go through a shell (`PTY.spawn` receives an explicit argv, not a `sh -c` string), this Ruby-level interpolation is the *sole* gate that is supposed to restrict which environment values a step body can see and echo/exfiltrate. The `permit`/whitelist mechanism (`filter_deploy_envs`, `filter_rollback_envs`) is designed precisely to prevent a step from touching values outside the declared variable set, but `interpolate`'s fallback bypasses it entirely for any name that happens to exist in the host process environment — which commonly includes operational secrets for a colocated Rails/Shipit deployment (`DATABASE_URL`, `SECRET_KEY_BASE`, `REDIS_URL`, etc.), not just stack-scoped deploy variables.

None of the existing guards address this: `verify_signature`, `force_github_authentication`, `require_permission!`, and the `stacks` scope govern who can trigger tasks/webhooks, not what a permitted deploy/rollback step can read once it runs; `EnvironmentVariables#permit` only filters variables that are explicitly present in the sanitized hash — it never touches the `interpolate` fallback path.

### Impact Explanation
An attacker who can get their `shipit.yml` executed as a deploy or rollback step (via a PR-triggered task definition or a review-stack build using their branch) can reference any environment variable name that happens to be exported in the Shipit host process — including secrets never intended to be exposed to repository-scoped deploy scripts — and have that value shell-escaped straight into the step's argv, where it can be echoed, curled to an attacker-controlled endpoint, or otherwise leaked through task output. This is a real exfiltration of host/deploy-time secrets and matches the Critical "exfiltration of deploy-time secrets" category. The blast radius is limited to secrets present in the Shipit host process's `ENV`, and is repeatable on every task run for any repository configured to allow attacker-influenced task/step definitions.

### Likelihood Explanation
Requires (a) a Shipit deployment where PR/branch-controlled `shipit.yml` content is used to define deploy/rollback steps (e.g., review stacks or PR-triggered task definitions), and (b) the Shipit host process to actually export the targeted secret as an environment variable (common when a Rails app and its Shipit worker are colocated and share `.env`/`ENV`). Given those preconditions, exploitation cost is trivial — a single line in `shipit.yml` — and fully repeatable.

### Recommendation
Remove the `ENV[variable]` fallback in `EnvironmentVariables#interpolate` (lib/shipit/environment_variables.rb:25); unresolved/whitelisted-missing variables should raise or interpolate to an empty string, never fall through to the Shipit process's own `ENV`.

### Proof of Concept
```ruby
# test/unit/environment_variables_test.rb (illustrative)
test "#interpolate does not fall back to process ENV for unlisted variables" do
  ENV['DATABASE_URL'] = 'postgres://attacker-leak-target'
  command = Shipit::Command.new(
    'echo $DATABASE_URL',
    env: {}, # simulates filtered_rollback_env with DATABASE_URL not whitelisted
    chdir: '/tmp'
  )
  refute_includes command.interpolated_arguments.join(' '), 'attacker-leak-target'
ensure
  ENV.delete('DATABASE_URL')
end
```
Currently this assertion fails: `interpolated_arguments` contains the value of `ENV['DATABASE_URL']` even though it was never part of the whitelisted `env` hash, confirming the whitelist bypass at lib/shipit/environment_variables.rb:25.