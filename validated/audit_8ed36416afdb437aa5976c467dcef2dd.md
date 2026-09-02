### Title
Unauthenticated cross-repository webhook forgery via `repository.owner.login`/`repository.full_name` binding gap lets a "no-secret organization" be used to inject attacker-controlled env vars into any existing review stack through `LabelCapturingHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC secret) using only `repository.owner.login`, while every `pull_request` handler (including `LabelCapturingHandler`) independently resolves the target `Repository`/`Stack` using the separate `repository.full_name` field. Since neither the controller nor any handler cross-checks that these two fields agree, an org configured in Shipit with a blank `webhook_secret` can be used to pass signature verification while `repository.full_name` is forged to point at a completely different, properly-secured victim repository, letting `LabelCapturingHandler` overwrite that victim stack's `PullRequest#labels`, which are subsequently injected as uppercased environment variables via `ReviewStack#env`.

### Finding Description
Broken binding (equality that must hold but doesn't): `params.dig('repository','owner','login')` used in `verify_signature` **must equal** the owner segment of `params.repository.full_name` used by every handler to resolve `Shipit::Repository.from_github_repo_name`. Nothing enforces this:

- `verify_signature` picks the app config solely from `repository_owner`: [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's `webhook_secret` is blank: [3](#0-2) 
- `LabelCapturingHandler` (and every other pull_request handler) instead resolves the repository from the independent `repository.full_name` field: [4](#0-3) 

Exploit flow: attacker finds/creates a GitHub organization that is registered in Shipit's `github` config but has no `webhook_secret` set (a "no-secret organization"). They POST to `/webhooks` with header `X-Github-Event: pull_request`, body `action: "unlabeled"`, `repository.owner.login = "no-secret-org"` (so `verify_signature` picks that org's `GitHubApp`, whose blank secret makes `verify_webhook_signature` return `true` with no valid HMAC needed), but `repository.full_name = "victim-org/victim-repo"` pointing at an unrelated, properly-secured repository that already has an active `ReviewStack` (e.g., `pr42`). `LabelCapturingHandler#capture_labels?` requires only `unlabeled? && stack.present? && !stack.archived?` — it does **not** check `review_stacks_enabled** at all — so if `victim-org/victim-repo`'s `pr42` review stack already exists, `capture_labels` overwrites `PullRequest#labels` with the attacker's forged label names: [5](#0-4) [6](#0-5) 

Those labels are then merged as uppercased environment variables into the stack's deploy/task environment: [7](#0-6) 

**Correction to the question's specific framing:** the "`provision?` precedence bug" (`repository.review_stacks_enabled && provisioning_behavior_allow_all? || ...`) is real but lives only in `OpenedHandler#provision?`/`ReopenedHandler#unarchive?`, reachable only via `action == "opened"`/`"reopened"`: [8](#0-7) 
It is **not** reachable through `action == "unlabeled"`, and `LabelCapturingHandler` never provisions anything — `review_stack.stack` calls `scope.find_by(environment:)`, never `create!`: [9](#0-8) 
So the compound claim "unlabeled → LabelCapturingHandler → provision? precedence bug still provisions despite review_stacks_enabled false" is inaccurate — `LabelCapturingHandler` can only mutate an **already existing** `ReviewStack`, and `review_stacks_enabled` is irrelevant to this handler entirely (it's simply never checked). `UnlabeledHandler` itself correctly ANDs `review_stacks_enabled` and is not vulnerable to the precedence issue: [10](#0-9) 

### Impact Explanation
An unprivileged internet attacker who controls (or registers) any GitHub organization that happens to be configured in Shipit with a blank `webhook_secret` can forge a `pull_request`/`unlabeled` webhook that is authenticated as that org, yet whose `repository.full_name` targets an arbitrary, unrelated, properly-secured victim repository's existing review stack. This lets the attacker overwrite `PullRequest#labels` and inject arbitrary attacker-chosen environment variable names (uppercased, value `"true"`) into that victim stack's deploy environment via `ReviewStack#env`, which is merged into the environment passed to the stack's `Command`/task execution. This is "a payload for one repository mutating another's stack" (Critical category) — environment-variable injection into a foreign tenant's deploy pipeline can influence build/deploy tooling behavior and is repeatable against any victim repository that has a pre-existing review stack, for as long as at least one no-secret org exists in the Shipit config.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization registered in Shipit's `github` app config with a blank `webhook_secret` (an operator misconfiguration, but one the code silently accepts as "no signature required" rather than rejecting/warning), (2) a victim repository with `review_stacks_enabled` and an already-provisioned `ReviewStack` for some PR number (a common, unprivileged-attacker-observable state — the attacker can open their own PR against the victim repo to create it first, if allowed, or wait for any existing PR-stack). Attacker cost is a single unauthenticated HTTP POST with no valid signature required, fully repeatable and scriptable against many victim repositories sharing the same no-secret org bypass.

### Recommendation
In `WebhooksController#verify_signature`, additionally validate that `params.dig('repository','full_name')` is consistent with `repository.owner.login`/`repository.name` (or better, resolve the target `Repository` first and use *that* repository's own configured GitHub App/secret for signature verification, not a secret derived from an independently-attacker-supplied field). Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` when `webhook_secret` is blank — it should fail closed (reject) unless webhook verification is explicitly disabled for a documented reason. Also add a `review_stacks_enabled` guard in `LabelCapturingHandler#capture_labels?` for defense in depth.

### Proof of Concept
Minitest plan (in `test/controllers/shipit/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb`):
1. Configure two orgs in `Shipit.github_configs`/`Rails.application.secrets`: `"no-secret-org"` with no `webhook_secret`, and `"victim-org"` with a real `webhook_secret`.
2. Create `shipit_repositories(:victim)` under `victim-org/victim-repo`, and an existing `Shipit::ReviewStack` with `environment: "pr42"`, plus its `pull_request` record with `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, body: `{"action":"unlabeled","number":42,"repository":{"owner":{"login":"no-secret-org"},"full_name":"victim-org/victim-repo"},...,"pull_request":{...,"labels":[{"name":"malicious_env"}]}}`.
4. Assert response is `200`/`204` (not `422`), proving signature bypass.
5. Assert `victim_stack.pull_request.reload.labels == ["malicious_env"]` and `victim_stack.env["MALICIOUS_ENV"] == "true"`, proving cross-tenant environment injection into a repository that never authenticated the request — violating the stated invariant "A pull_request event only affects the repository/stack whose secret authenticated it."

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L66-68)
```ruby
          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-84)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
