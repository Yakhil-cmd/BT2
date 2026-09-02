### Title
Webhook signature verification org (`repository.owner.login`) is decoupled from the repository actually mutated (`repository.full_name`), letting one repo's payload write another repo's `PullRequest`/`ReviewStack` state - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` used to validate the HMAC solely from `params.dig('repository','owner','login')` (`repository_owner`), while every `pull_request` handler — including `LabelCapturingHandler` — resolves the target `Repository`/`Stack` solely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`. Because nothing enforces that `full_name`'s owner segment matches `repository.owner.login`, an attacker can authenticate against an org with no (or a known) `webhook_secret` while pointing `full_name` at a victim org/repo whose stack has `blocking_statuses` configured, causing `LabelCapturingHandler` to write attacker-controlled labels onto that victim's `PullRequest`.

### Finding Description
The broken binding, stated as an equality that the code never enforces:
`org_used_for_signature = params.dig('repository','owner','login')` must equal `org_owning(params.repository.full_name)` — but these are read from two independent, attacker-controlled JSON fields with no cross-validation anywhere in the path.

Trace:
- `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) reads `params.dig('repository','owner','login')` (or `organization.login`). [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that org (`lib/shipit/github_app.rb:76-83`). So any org with `webhook_secret` unset (or one whose secret is known to the attacker, e.g. their own onboarding org) always passes verification. [3](#0-2) 
- Once verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the **same raw params** to handlers (`app/controllers/shipit/webhooks_controller.rb:10-15`), none of which re-check `repository.owner.login`. [4](#0-3) 
- `LabelCapturingHandler#repository` resolves the acted-upon repository purely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114`), and `Repository.from_github_repo_name` simply splits the string on `/` and does a DB lookup with no relation to `owner.login` (`app/models/shipit/repository.rb:53-56`). [5](#0-4) [6](#0-5) 
- On `action == "labeled"` for a present, non-archived stack, `capture_labels` persists `params.pull_request.labels.map(&:name)` onto that stack's `PullRequest#labels` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`). [7](#0-6) 
- `ReviewStack#env` then merges each stored label, upcased, as `"true"` into the stack's runtime environment: `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" } ` (`app/models/shipit/review_stack.rb:84-93`). [8](#0-7) 
- Separately, `Commit#blocked?` gates deploys based on `stack.blocking_statuses` and whether any reachable, undeployed prior commit `blocking?` (`app/models/shipit/commit.rb:231-237`), and `Status#blocking?` depends on `commit.blocking_statuses.include?(context)` (`app/models/shipit/status/common.rb:46-48`). These are driven by GitHub status webhooks (a separate handler), not by `LabelCapturingHandler` directly — the label write itself does not set/clear `blocked?`; it injects arbitrary uppercase environment variables into the victim stack's deploy/task environment. [9](#0-8) [10](#0-9) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, a body where `repository.owner.login` = some org with no configured `webhook_secret` (or a public/no-secret org they control), but `repository.full_name` = `"victim-org/victim-repo"` whose review stack exists and has an open, non-archived `PullRequest`. `action = "labeled"`, `labels = [{name: "<ARBITRARY_ENV_KEY>"}]`. Signature check passes trivially against the no-secret org; the handler then resolves and mutates the victim repository's `PullRequest.labels`, and those labels become injected environment variables (`ENV[X]=true`) for every subsequent task/deploy on that review stack via `ReviewStack#env`.

This is a genuine cross-tenant write: the party that "authenticated" the request (the no-secret org) is not the party whose data is mutated (the victim org/repo). None of the listed guards (`drop_unhandled_event`, `ExplicitParameters` schema, `force_github_authentication`, model validations) check that `full_name`'s owner matches the org used to select the `GitHubApp`/verify the signature — the schema only requires `repository.full_name` to be a `String`, and `Repository.from_github_repo_name` performs no ownership cross-check.

### Impact Explanation
An unprivileged attacker (owning any repo, or simply able to send arbitrary HTTP to `/webhooks`) can write to `PullRequest#labels` on a victim's `ReviewStack` that they do not own, and those labels become environment variables injected into that stack's task/deploy environment (`ReviewStack#env`). This is a cross-repository state write triggered by an unauthenticated-for-that-repo request, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius covers any victim repository/stack whose full_name the attacker can guess or knows (organization/repo names are typically public), and the attack is fully repeatable per request with no rate limiting concerns considered.

### Likelihood Explanation
Preconditions: (1) at least one GitHub org configured in Shipit with no `webhook_secret` set (common misconfiguration, or the attacker's own onboarding org added to the Shipit instance), (2) knowledge of a target org/repo name with a review stack and open PR — both are generally discoverable/public information, (3) no other secret is required since `verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank. The attacker cost is a single crafted HTTP POST with correct headers (`X-Github-Event: pull_request`) and JSON body; no GitHub account, Shipit session, or API token is required. This is fully repeatable against any repository/stack whose name the attacker knows.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, derive the GitHub org used for signature verification consistently with the repository actually resolved by handlers — i.e., after (or as part of) signature verification, assert that `params.dig('repository','owner','login')` matches the owner segment of `params.dig('repository','full_name')` (case-insensitively), and reject (422) if they diverge. Additionally, harden `GitHubApp#verify_webhook_signature` (or its caller) to fail closed when `webhook_secret` is not configured for an organization that owns repositories with review stacks, rather than silently returning `true`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "labeled event authenticated by no-secret org mutates a different org's stack" do
  # Precondition equality that should hold but doesn't:
  # repository_owner_used_for_signature == owner_of(repository.full_name)
  no_secret_org = "attacker-org"        # Shipit.github(organization: no_secret_org) has no webhook_secret
  victim_repo    = shipit_repositories(:shipit) # has blocking_statuses configured stack + open PR
  victim_stack   = victim_repo.review_stacks.first # or a stack with pull_request present

  payload = {
    action: "labeled",
    number: victim_stack.pull_request.number,
    pull_request: {
      id: 1, number: victim_stack.pull_request.number, url: "http://x", title: "t", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "INJECTED_ENV" }]
    },
    repository: {
      owner: { login: no_secret_org },        # used ONLY for signature org selection
      full_name: victim_repo.github_repo_name # used to resolve the mutated repository/stack
    },
    sender: { login: "attacker" }
  }.to_json

  post "/webhooks", params: payload,
       headers: { "X-Github-Event" => "pull_request", "Content-Type" => "application/json" }
       # no X-Hub-Signature needed / any value works because webhook_secret is blank for no_secret_org

  assert_response :ok

  # Assert the binding is broken: the org that "authenticated" (no_secret_org)
  # is not the org whose PullRequest/labels/env got mutated (victim_repo's owner).
  victim_stack.pull_request.reload
  assert_includes victim_stack.pull_request.labels, "INJECTED_ENV"
  assert_equal "true", victim_stack.env["INJECTED_ENV"]
  refute_equal no_secret_org, victim_repo.owner
end
```

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
