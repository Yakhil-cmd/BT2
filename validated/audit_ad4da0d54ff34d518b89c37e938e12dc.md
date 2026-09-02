### Title
Cross-Organization Commit Status Forgery via Unscoped `sha` Lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the GitHub App configured for `repository_owner` (the organization named in the signed payload's `repository.owner.login`), but `Shipit::Webhooks::Handlers::StatusHandler#process` never re-checks that binding when writing the status: it looks up commits solely `Commit.where(sha: params.sha)`, with no scoping by the payload's `repository`/organization. This breaks the equality "organization whose `webhook_secret` authenticated the request" == "repository/organization whose commit is written."

### Finding Description
The webhook signature check only proves the request was signed by the GitHub App belonging to `repository_owner`, computed from the payload itself: [1](#0-0) [2](#0-1) 

Once verified, the controller dispatches to handlers with the raw parsed payload: [3](#0-2) 

Most handlers correctly re-derive the target repository from `payload.dig('repository', 'full_name')` via the base `Handler#stacks` helper: [4](#0-3) 

`StatusHandler`, however, bypasses this scoping entirely and matches commits globally by SHA across the whole Shipit instance, independent of which repository/organization the payload claims or which organization's secret verified the signature: [5](#0-4) 

Because `Shipit.github(organization:)` config is per-organization (each org has its own `webhook_secret`, per `lib/shipit.rb`'s multi-org config and `test/dummy/config/secrets_double_github_app.yml`), any organization/repository legitimately configured in the same Shipit instance can authenticate with its own valid signature and still cause the `StatusHandler` to write a status onto a commit belonging to a completely different, unrelated repository/organization also hosted on that Shipit instance — as long as the attacker knows or guesses that commit's SHA (trivially obtainable for any public repository, or via Shipit's own UI/API which exposes SHAs).

### Impact Explanation
Shipit's deploy/merge gating relies on commit statuses (`Status`/`Status::Group`, CI checks referenced in `deploy_spec.rb`, `merge_request.rb`) to decide whether a commit is deployable or mergeable. An attacker who controls (or has webhook access to) any one org/repo tracked by the shared Shipit instance can forge a `success` status for a specific commit SHA in an entirely different, victim organization's repository tracked by the same instance, potentially satisfying required-status checks and enabling an unauthorized deploy or merge of code that never actually passed CI. This is a cross-repository/cross-organization write achieved purely by exploiting the deployment-trust binding gap (payload's declared org vs. actually written repository), consistent with the "unauthorized deploy" impact category.

### Likelihood Explanation
Requires the attacker to control (or compromise) at least one organization already configured with the Shipit engine's `github.<org>.webhook_secret` (a realistic multi-tenant setup, as shown by the dummy multi-org secrets fixture), and to know a target commit SHA in another tracked repository — both are plausible without any Shipit session, API token, or GitHub write access to the victim repository, matching the "unprivileged attacker" threat model in this analysis. No other handler in the codebase has this gap; `PushHandler` and `CheckSuiteHandler` correctly scope through `Handler#stacks`.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository resolved from the payload (e.g., via the inherited `stacks`/`repository_name` helpers), and reject/ignore statuses whose commit's stack repository does not match the authenticated `repository_owner`, mirroring the scoping already used by `PushHandler` and `CheckSuiteHandler`.

### Proof of Concept
1. Attacker controls org `attacker-org`, which is configured in Shipit with its own valid `webhook_secret` (a normal, legitimate onboarding).
2. Attacker learns (e.g., from GitHub's public commit history or Shipit's own UI) the SHA of a commit `abc123...` belonging to `victim-org/victim-repo`, also tracked by the same Shipit instance.
3. Attacker sends a `status` webhook event signed with `attacker-org`'s `webhook_secret`:
   ```
   X-Github-Event: status
   X-Hub-Signature: sha1=<valid signature for attacker-org>
   { "sha": "abc123...", "state": "success", "context": "ci/required-check",
     "repository": {"owner": {"login": "attacker-org"}} }
   ```
4. `verify_signature` succeeds because it authenticates against `attacker-org`'s secret using `repository_owner = "attacker-org"` from the payload.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, finds the victim's commit (owned by `victim-org/victim-repo`), and calls `commit.create_status_from_github!(params)`, writing a forged `success` status onto a commit in a repository the attacker never controlled.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
```
