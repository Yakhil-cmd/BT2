### Title
Signature verification is bound to `repository.owner.login`/`organization.login` while the mutated stack is resolved via the independently-attacker-controlled `repository.full_name`, letting a forged `pull_request` `reopened` webhook for a no-secret org write attacker-chosen labels/env keys onto any other org's review stack - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing secret using `repository_owner`, which is read straight from the attacker-supplied JSON body (`params.dig('repository','owner','login')`), while `Shipit::GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org has no `webhook_secret` configured. The handler that actually mutates state (`LabelCapturingHandler`, and the base `Handler#stacks`) independently resolves the target repository from a *different* JSON field, `params.dig('repository','full_name')`. Because these two attacker-controlled fields need not match, a request that "authenticates" against a no-secret org can carry a `full_name` pointing at an entirely different, properly-secured organization's stack, letting the attacker overwrite that stack's `PullRequest#labels`, which become uppercased environment variables injected into every subsequent `shipit.yml` command execution on that stack.

### Finding Description
The broken binding: the code implicitly assumes
`repository_owner (used for signature verification) == owner(repository.full_name) (used for the state mutation)`,
but nothing enforces this equality - both are independent leaves of the same attacker-controlled JSON body.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` purely from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the resolved org config: `return true unless webhook_secret`. [3](#0-2) 
- Once past `verify_signature`, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw parsed body, unmodified, to handlers. [4](#0-3) 
- `LabelCapturingHandler#repository` resolves the target `Repository` from `params.repository.full_name` - a field that is never cross-checked against `repository.owner.login` used in the earlier signature step. [5](#0-4) 
- For `action == "reopened"` on an existing, non-archived stack, `capture_labels?` is true and `capture_labels` runs `pull_request.update!(labels: params.pull_request.labels.map(&:name))` - fully attacker-controlled label strings, unvalidated beyond `String` typing in the `ExplicitParameters` schema. [6](#0-5) [7](#0-6) 
- `ReviewStack#env` merges those labels, uppercased, as environment-variable keys with value `"true"` into the environment used for command execution: `labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }`. [8](#0-7) 
- This merged env reaches `DeployCommands#env`/`TaskCommands#env` unfiltered, confirmed by existing tests asserting `env["WIP"] == "true"` for injected labels - i.e., these attacker-chosen keys flow into the process environment used to run `shipit.yml` commands. [9](#0-8) [10](#0-9) 

Existing guards do not prevent this: `verify_signature` only checks that *some* org lacking a secret validated the request; it never re-derives or compares that org against the org actually being mutated. `drop_unhandled_event` and the `ExplicitParameters` schema (`requires :full_name, String`, `requires :name, String`) only enforce types/presence, not cross-field consistency or ownership. [11](#0-10) 

Exploit flow: attacker identifies (a) any GitHub organization onboarded to this Shipit instance that has no `webhook_secret` configured, and (b) a victim organization/repo with `review_stacks_enabled: true, allow_all` that already has a provisioned, non-archived review stack for some open PR (auto-created because `allow_all` provisions stacks for any external PR). The attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, an arbitrary/absent `X-Hub-Signature`, and a JSON body where `repository.owner.login`/`organization.login` is set to the no-secret org (satisfying `verify_signature`) but `repository.full_name` and `pull_request.number` point at the victim's real repo/PR. `LabelCapturingHandler` then overwrites the victim stack's `PullRequest#labels` with attacker-chosen strings, which become forced environment-variable keys for every subsequent deploy/task run on that stack.

### Impact Explanation
The attacker achieves an unauthenticated, cross-tenant write: a `PullRequest#labels` record for a repository/stack the request did not actually authenticate against is overwritten, and those attacker-chosen keys are injected as environment variables into the shell environment used to execute `shipit.yml`-defined deploy/task commands on that stack (`Command`/`PTY.spawn` pipeline referenced by `DeployCommands#env`/`TaskCommands#env`). Because `review_stacks_enabled: true, allow_all` means such stacks execute `shipit.yml` automatically on PR events, the attacker can inject arbitrary environment-variable *names* (value fixed to `"true"`) - e.g., variables that shadow tool configuration (`BUNDLE_GEMFILE`, `RUBYOPT`, `PATH`-adjacent flags used by the deploy scripts) - into a build/deploy process they never authenticated against. This matches the "payload for one repository mutating another's stack" Critical class, and depending on `shipit.yml` content in the victim repo, can escalate to command/argument injection or RCE on the deploy host. This is repeatable against any org pairing where a no-secret org exists in the Shipit config, for arbitrary repositories with active review stacks.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization configured in this Shipit instance without a `webhook_secret` (a known, documented misconfiguration risk called out in `docs/setup.md`), and (2) a target repository with `review_stacks_enabled: true, allow_all` and an existing non-archived review stack (trivially obtained since `allow_all` auto-provisions stacks for any external PR, including one the attacker themselves opens). No GitHub secrets, Shipit session, or API token are required - only knowledge of the no-secret org's name and the victim repo's `full_name`/PR number, both of which are either public or self-created by the attacker. This is a cheap, repeatable, unauthenticated HTTP POST.

### Recommendation
Bind signature verification to the same repository/organization the handler subsequently mutates: derive `repository_owner` and the target `Repository`/`Stack` from the same trusted lookup (e.g., resolve the `Repository` record first, then verify the signature using that repository's actual configured organization secret, not a value taken from a second, independently-controlled JSON field). Additionally, require every onboarded organization to have a non-blank `webhook_secret` and refuse requests (`head 422`) instead of treating a missing secret as automatically verified in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure two orgs in `Shipit.github_apps` test config: `"no-secret-org"` with `webhook_secret` blank, and `"victim-org"` with a real `webhook_secret`.
2. Create `victim-org/victim-repo` with `provisioning_behavior: allow_all`, `review_stacks_enabled: true`, and a pre-existing non-archived `ReviewStack` with `environment: "pr123"` and a `PullRequest` with `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, and body:
   ```json
   {
     "action": "reopened",
     "number": 123,
     "pull_request": { "...": "...", "labels": [{"name": "RUBYOPT"}] },
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "no-secret-org" } },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert the response is `200`/`204` (not `422`), i.e. `verify_signature` passed via the `no-secret-org` binding: `assert_response :success`.
5. Assert the divergence: `assert_equal ["RUBYOPT"], victim_stack.reload.pull_request.labels` and `assert_equal "true", victim_stack.env["RUBYOPT"]`, proving a request "authenticated" against `no-secret-org` produced a state change on `victim-org`'s stack, which it never authenticated.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-72)
```ruby
          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

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

**File:** test/lib/shipit/deploy_commands_test.rb (L6-15)
```ruby
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```
