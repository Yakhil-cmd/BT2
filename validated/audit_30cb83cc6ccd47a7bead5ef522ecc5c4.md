### Title
Fork PR labels inject unsanitized environment variables (e.g. `LD_LIBRARY_PATH`) into `Command#start` for `ReviewStack` deploys - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the environment hash with no allowlist, and `Command#unbundled_env` merges that hash last, overriding any base environment key including `LD_LIBRARY_PATH` or `PATH`. Since an unprivileged fork PR fully controls its own label set and its own repository checkout (the `chdir` used by `Command#start`), it can set `LD_LIBRARY_PATH` and simultaneously plant a matching directory containing a malicious shared object in the checked-out tree, causing dynamic-linker hijacking for any dynamically-linked binary invoked during the `deploy.override` step.

### Finding Description
The broken binding: `ReviewStack#env` should equal `super` (the sanitized/allowlisted stack env) for any repo, but instead it equals `super.merge(labels_hash)` where `labels_hash` has arbitrary attacker-chosen keys:

```
super.merge(pull_request.labels.each_with_object({}) { |n,h| h[n.upcase] = "true" })
``` [1](#0-0) 

`labels` themselves come straight from the webhook payload with no allowlist on names — `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim: [2](#0-1) 

The schema for the webhook only requires `name` to be a `String`, with no format restriction, so any label text (including `ld_library_path`, `path`, etc.) is accepted: [3](#0-2) 

That env hash flows down to `Command`, where `unbundled_env` merges `@env.stringify_keys` **last**, after `BASE_ENV` and the constructed `PATH`, with no denylist/allowlist of dangerous keys:
```
BASE_ENV.merge('PATH' => "...").merge(@env.stringify_keys)
``` [4](#0-3) 

and this is exactly what is passed to `PTY.spawn`: [5](#0-4) 

Note that `EnvironmentVariables#permit` (the actual sanitizer with a real allowlist) exists in the codebase and is used elsewhere (e.g. interpolation of `deploy.override` command arguments), but it is never applied to the label-derived hash produced by `ReviewStack#env` — that hash bypasses `permit` entirely and is merged unconditionally. [6](#0-5) 

Exploit flow: an attacker opens a PR from their own fork against a repo with `provisioning_behavior=allow_all`, applies a label literally named `ld_library_path` (case-insensitive, since it's uppercased anyway) to their own PR, and commits a directory literally named `true` (matching the fixed value `"true"` that `ReviewStack#env` always assigns) inside their fork's tree containing a malicious shared object whose name collides with a library dynamically resolved by name (not by absolute path) by a binary invoked in the `deploy.override` section. Because `Command#start` uses the fork's checkout as `chdir`, and `LD_LIBRARY_PATH=true` is a relative path resolved against the current working directory, the dynamic linker preferentially loads the attacker's `.so` for any such invocation.

Existing guards do not stop this: `verify_signature`/webhook signature checks only validate that the payload came from GitHub for the repository in question — they say nothing about label *content*, which is fully attacker-controlled since the attacker owns the PR/fork; `ExplicitParameters` only requires `name` be a `String`; there is no `EnvironmentVariables#permit` call along this specific path.

### Impact Explanation
This lets any fork-PR author on a repo with `allow_all` provisioning cause arbitrary dynamically-linked binaries invoked by the `deploy.override` step to load an attacker-supplied shared object — i.e., arbitrary code execution on the Shipit deploy host, scoped to that repository's review-stack deploy process. It is repeatable per-PR (each PR/label update re-triggers `capture_labels` and the env is recomputed on every `Command#start` call for that stack). Blast radius is limited to review stacks of repositories explicitly opted into `allow_all` provisioning, but within that scope it is full command-environment control, matching the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category.

### Likelihood Explanation
Preconditions: the target repository must be configured with `provisioning_behavior=allow_all` (an explicit opt-in by the repo maintainer), and the review app's `shipit.yml` `deploy.override` step must invoke a binary that dynamically resolves a library by short name rather than an absolute/RPATH-embedded path. Attacker cost is trivial — open a PR from a fork, add one label, and add a directory named `true` with a crafted shared object to the fork's tree. No secrets, tokens, or privileged roles are required. Feasibility depends on the specific `deploy.override` commands executed by the target's `shipit.yml`, so exploitability is repo-configuration-dependent but requires no special access beyond what any GitHub user already has (opening PRs/labels on their own fork PR against a public repo that reviews forks).

### Recommendation
In `ReviewStack#env`, route the label-derived hash through `EnvironmentVariables#permit` with an explicit allowlist (e.g., only variables declared by the repo's `shipit.yml` `env` section), and reject/strip any label name that collides with sensitive process environment keys (`LD_LIBRARY_PATH`, `LD_PRELOAD`, `PATH`, `IFS`, etc.). Additionally, `Command#unbundled_env` should apply a denylist of dynamic-linker-related variables that can never be overridden by task/stack env regardless of source.

### Proof of Concept
```ruby
test "review stack env injects LD_LIBRARY_PATH from a PR label, unsanitized" do
  stack = shipit_review_stacks(:review_stack) # or build one
  pull_request = stack.pull_request
  pull_request.update!(labels: ["ld_library_path"])

  env = stack.env
  assert_equal "true", env["LD_LIBRARY_PATH"], "attacker label overrides LD_LIBRARY_PATH with no allowlist"

  command = Shipit::Command.new("echo", chdir: Dir.mktmpdir, env: env)
  spawned_env = command.unbundled_env
  assert_equal "true", spawned_env["LD_LIBRARY_PATH"], "unsanitized key reaches Command#start / PTY.spawn"
end
```
This demonstrates the equality break: `stack.env["LD_LIBRARY_PATH"]` should be absent/blocked (LHS = `nil`) but is actually `"true"` (RHS), and that value survives unmodified into `Command#unbundled_env`, the hash passed to `PTY.spawn`.

### Citations

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/command.rb (L92-92)
```ruby
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
