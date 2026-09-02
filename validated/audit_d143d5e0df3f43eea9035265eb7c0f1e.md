## Analysis

The reported bug class (a control that "locks" a resource but has no way to correct it once trust assumptions are violated) maps into shipit-engine as a broken binding between **the environment keys a deploy/task is *permitted* to receive from an HTTP request** and **the environment keys a spawned shell command can actually resolve** while executing untrusted, PR-supplied `shipit.yml` content.

`EnvironmentVariables.permit` (`lib/shipit/environment_variables.rb:13-18,35-44`) enforces a whitelist only for the `env` hash **explicitly passed in an API/UI request** (`Stack#trigger_task`, `Stack#build_deploy`, `TaskDefinition#filter_envs`). This whitelist is the only guard the code exposes to operators for "which variables can be user-controlled."

But `EnvironmentVariables#interpolate`, used by `Command#interpolated_arguments` when spawning every deploy/task/review step (`lib/shipit/command.rb:51-55,81-83,92`), resolves any `$VARNAME` token found **inside the shell command line itself** (which comes straight from `shipit.yml`, not from the whitelisted `env` hash) with:

```ruby
Shellwords.escape(@env.fetch(variable) { ENV[variable] })
``` [1](#0-0) 

If the variable name is not present in the task's merged `@env`, it silently falls back to Ruby's global `ENV` — i.e., the **Shipit application/worker process's own environment**, which is where deploy-host secrets (API keys, DB URLs, GitHub App credentials, etc.) typically live.

`shipit.yml` (including `review.checks` and `deploy.override` steps) is read straight from the branch being built — `DeploySpec::FileSystem#config_file_path`/`#load_config` (`app/models/shipit/deploy_spec/file_system.rb:98-143`) — and for a Review Stack that branch is the **pull request's own head ref**, set directly from the webhook payload:

```ruby
def stack_attributes
  { branch: params.pull_request.head.ref, environment:, ... }
end
``` [2](#0-1) 

Review Stacks are auto-provisioned purely from GitHub PR webhook events (`opened`, `labeled`, `reopened`, etc. — see `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`, `labeled_handler.rb`) when a repository's `provisioning_behavior` is `allow_all` or `allow_with_label`. In either mode, the actor who controls the `shipit.yml` content that gets executed on the deploy host is the **PR author**, who needs no write access to the repository — only the ability to open a pull request (from a fork).

## Result

Because `interpolate`'s fallback reads the *real* process environment rather than only the vetted `@env` hash, a PR author can put, e.g., `review.checks: - "echo $SOME_HOST_SECRET"` in their fork's `shipit.yml`. When the Review Stack automatically runs that check, Shipit spawns the command after substituting `$SOME_HOST_SECRET` with the actual value from the Shipit process's `ENV`, and the result is streamed to task output that the PR author can view via the stack/task pages. This lets an unprivileged, external, repository-write-less user exfiltrate whatever secrets happen to be present in the Shipit deploy host's process environment — the exact class of "authorization/lock bypassed because there's no way to constrain what was inherited after the fact" described in the source report, here expressed as **permitted env-keys (whitelist) vs. spawned env-keys (raw process ENV fallback)**.

## Caveats

- I could not verify from the index what secrets are actually placed in the Shipit process's `ENV` in a given deployment (this is host/operator-specific), nor the default value of `provisioning_behavior` (the repository-level opt-in flag) — this reduces certainty about real-world blast radius, though the code path itself is unambiguous. [3](#0-2) 
- Confirming exactly which review/deploy steps run pre-merge (i.e., without any maintainer approval) for `allow_all` vs `allow_with_label` repositories would benefit from reading `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb` and `labeled_handler.rb` in full — I saw strong indirect evidence (tests, `ReviewStackAdapter`) but not the complete handler bodies. If you need the exact conditions, I'd recommend starting a full Devin session to read `app/models/shipit/webhooks/handlers/pull_request/*.rb` end-to-end and confirm.

### Citations

**File:** lib/shipit/environment_variables.rb (L20-27)
```ruby
    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/repository.rb (L1-1)
```ruby
# frozen_string_literal: true
```
