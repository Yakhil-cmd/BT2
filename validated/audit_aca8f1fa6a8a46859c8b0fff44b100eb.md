This confirms the multi-org config setup: `Shipit.github(organization: repository_owner)` resolves per-org config via `github_app_config`, and if an org has no `webhook_secret`, `GitHubApp#verify_webhook_signature` unconditionally returns `true`.### Title
Organization fallback in `repository_owner` decouples webhook signature verification from the repository the handler mutates, allowing forged `pull_request` events to write labels onto any repository's review stack — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which org's `GitHubApp` (and thus which `webhook_secret`) validates a webhook using `repository_owner`, which falls back to `params.dig('organization','login')` when `params['repository']['owner']['login']` is absent. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler`, however, resolves the target repository from the independent field `params.repository.full_name`. Because these two fields are never cross-checked, and at least one configured GitHub org can lack a `webhook_secret` (making `GitHubApp#verify_webhook_signature` return `true` unconditionally), an attacker can forge a `pull_request` `opened`/`labeled`/`reopened` payload that is "verified" against the secret-less org while `repository.full_name` points at an entirely different, victim repository.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`repository_owner` (used in `WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb:59-62`) is assumed to equal the owner of `params.repository.full_name` (used in `LabelCapturingHandler#repository`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114`). In reality:

```ruby
# app/controllers/shipit/webhooks_controller.rb:59-62
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

and

```ruby
# app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) || NullRepository.new
end
``` [2](#0-1) 

These read from independently attacker-controlled JSON paths. `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` calls `Shipit.github(organization: repository_owner)` and checks `github_app.verify_webhook_signature`. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) contains `return true unless webhook_secret` — i.e., for any organization configured without a `webhook_secret`, **all signatures pass**, regardless of `X-Hub-Signature`. [3](#0-2) 

Root cause / exploit flow:
1. Attacker crafts a `pull_request` webhook body where the top-level `repository` object omits the nested `owner` key (satisfying the `requires :repository { requires :full_name }` schema, since `owner` is not required) but sets `repository.full_name` to the victim's repo, e.g. `"victim-org/victim-repo"`.
2. Attacker adds a top-level `organization.login` set to any org configured on the Shipit instance without a `webhook_secret` (e.g., a legacy/test org). `repository_owner` then falls back to this org's login.
3. `verify_signature` calls `Shipit.github(organization: "attacker-controlled-org")`, whose `GitHubApp` has `webhook_secret` blank, so `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` is required.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `LabelCapturingHandler`, which resolves `repository` from `params.repository.full_name` (the victim repo) via `Repository.from_github_repo_name`, and finds an existing review stack via `ReviewStackAdapter#stack` (`scope.find_by(environment: "pr#{params.number}")`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:15-17,96-98`).
5. If such a review stack already exists for the victim repo (e.g., a legitimately-open PR with that number), `capture_labels` runs: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) — fully attacker-controlled label strings are persisted onto the victim's `PullRequest` record, unauthenticated with respect to that repository.

Existing guards fail to close this gap: `verify_signature` never compares `repository_owner` against `params.repository.full_name`'s owner; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema for `LabelCapturingHandler` requires `repository.full_name` but not `repository.owner`, so the minimal/fallback payload validates cleanly; there is no cross-field consistency check anywhere in the dispatch path.

### Impact Explanation
An unauthenticated attacker (any internet user, no GitHub org membership, no Shipit credentials) can write attacker-chosen data (`labels`) into a `PullRequest` record belonging to a repository/organization that never authenticated the request — a payload for one repository mutating another's stack/record, matching the Critical impact category. Since these persisted labels are later uppercased into `ReviewStack#env` environment-variable keys, this can inject or shape arbitrary environment variable names into that victim review stack's environment, which is consumed by subsequent deploy/provisioning commands — extending the blast radius toward the deployment pipeline of a repository the attacker does not control. This is repeatable against any repository/organization whose review-stack PR number happens to exist, as long as any single org in the Shipit deployment's config lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: (a) the Shipit deployment has at least one configured GitHub organization without a `webhook_secret` in `secrets.github` (a realistic, commonly-seen misconfiguration/legacy state, e.g. staging orgs, since `GitHubApp#verify_webhook_signature` treats a blank secret as "trust everything"), and (b) the victim repository must already have an existing `ReviewStack` for the targeted PR number (i.e., an active review-stack PR). Attacker cost is a single unauthenticated HTTP POST to `/webhooks` with a hand-crafted JSON body and any `X-Hub-Signature` header (or none) — no secrets, no GitHub account actions on the victim repo needed. This is fully repeatable and scriptable.

### Recommendation
- In `WebhooksController#verify_signature`, derive `repository_owner` strictly from `params.repository.owner.login` when a `repository` object is present, and reject (422) the request if `repository` is present but `owner.login` is missing, rather than silently falling back to `organization.login`.
- Additionally, enforce that the org used to select the verifying `GitHubApp` matches the owner embedded in `params.repository.full_name` before dispatching to any handler.
- Treat an org configured without a `webhook_secret` as a configuration error (fail closed, reject the webhook) rather than "verified" (fail open) in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Under `test/controllers/shipit/webhooks_controller_test.rb` (or a new test file for "organization fallback selection"):

```ruby
test "pull_request opened forged via organization fallback affects an unrelated repository's stack" do
  # Setup: configure `secrets.github` with two orgs:
  #   "leaky-org" => { } (no webhook_secret)
  #   "victim-org" => { webhook_secret: "victim-secret" }
  # Precondition equality to assert BEFORE: the review stack's persisted labels
  # for victim-org/victim-repo PR #5 do NOT equal the attacker's chosen labels.
  stack = shipit_stacks(:review_stack) # belongs to victim-org/victim-repo, environment "pr5"
  pr = stack.pull_request
  assert_not_equal ["pwned"], pr.labels

  payload = {
    action: "opened",
    number: 5,
    pull_request: {
      id: 1, number: 5, url: "https://api.github.com/x", title: "t", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "some-branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "pwned" }]
    },
    repository: { full_name: "victim-org/victim-repo" }, # no nested owner.login
    organization: { login: "leaky-org" }, # forces fallback to secret-less org
    sender: { login: "attacker" }
  }.to_json

  post shipit.webhooks_path, params: payload, headers: {
    'Content-Type' => 'application/json',
    'X-Github-Event' => 'pull_request',
    'X-Hub-Signature' => 'sha1=bogus' # invalid/unrelated signature
  }

  assert_response :ok
  # Equality after: attacker-controlled labels were written to victim repo's PR
  # despite verification being performed against "leaky-org", not "victim-org".
  assert_equal ["pwned"], pr.reload.labels
end
```

This demonstrates `repository_owner` (verifier selector = `"leaky-org"`) diverging from the handler's `repository.full_name` owner (`"victim-org"`), with the divergence unguarded and directly leading to a write on a repository/stack that never authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
