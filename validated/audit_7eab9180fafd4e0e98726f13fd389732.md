Status handler confirms this pattern extends further: `StatusHandler` doesn't even filter by repository — it looks up `Commit.where(sha: params.sha)` globally across all stacks, no repository/org check at all (further widening the same trust gap).

### Title
Webhook signature verifies the claimed organization, but write targets are selected from an unverified repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook payload against the GitHub App/webhook secret of the organization named in `repository.owner.login` (falling back to `organization.login`), but every event handler that decides *which* `Stack`/`Repository`/`Commit` to mutate reads a different, unrelated field — `repository.full_name` (or, for `status`, no repository scoping at all). Nothing ties the two together, so a signature that is valid for organization A does not guarantee the payload only affects data belonging to organization A.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

It fetches `Shipit.github(organization: repository_owner)` and verifies the HMAC using that organization's `webhook_secret`: [3](#0-2) 

Once the signature is accepted, `params = JSON.parse(request.raw_post)` is handed unmodified to every registered handler for the event: [4](#0-3) 

The base `Handler` class — used by `PushHandler` and the `PullRequest::*` handlers — resolves the affected repository from `repository.full_name`, a field completely independent from `repository.owner.login`/`organization.login` used during signature verification: [5](#0-4) [6](#0-5) 

`StatusHandler` is even less scoped: it looks up `Commit.where(sha: params.sha)` with no repository/organization filter at all, and writes a `Status` for every matching commit across every stack in the installation: [7](#0-6) 

This is the same class of bug as the bonding-token report: a boundary condition (`liquidityGoalReached` / "is this signature valid for this action") is computed from one piece of state, while the actually-affected object (`token transferability` / `which repository/commit gets mutated`) is derived from a different, attacker-influenced piece of state that was never covered by the same check. Concretely, the equality the code implicitly relies on —

`organization_that_signed_the_payload == organization_that_owns_the_repository_being_written`

— is never enforced. `Shipit.github_teams`/OAuth authorization gates the web UI, but the webhook endpoint's only gate is `verify_webhook_signature`, and it authenticates the wrong field relative to what gets written.

### Impact Explanation
In a Shipit installation configured with more than one GitHub organization (a supported, documented configuration — "Support multiple GitHub organisations (#1151)"), each organization has its own `webhook_secret`. Anyone who legitimately possesses one organization's webhook secret (e.g., an administrator of Organization A's GitHub App/webhook settings, which is not a privileged Shipit account, `ApiClient` token, or GitHub-team-authorized user) can POST a self-crafted JSON body directly to `/webhooks` with:
- `repository.owner.login` / `organization.login` = `"OrgA"` (so `verify_signature` selects OrgA's secret and validates, since the attacker legitimately knows it)
- `repository.full_name` = `"OrgB/victim-repo"` (a repository/stack belonging to a different, unrelated tenant organization)

Because `PushHandler`, the `PullRequest::*` handlers, and `StatusHandler` never re-check that `repository.full_name`'s owner matches the organization whose secret authenticated the request, this yields cross-organization/cross-repository writes: forcing a `GithubSyncJob`/sync on another org's stack, injecting fabricated commit statuses (which feed CI gating used by `deployable?` and the merge queue) onto another org's commits, or spoofing pull-request opened/closed/labeled events to trigger review-stack provisioning/archival for a repository the attacker does not control. This crosses the "cross-repository writes" impact bar.

### Likelihood Explanation
Medium-to-High in any multi-organization Shipit deployment: the attacker needs no Shipit account, `ApiClient` token, or GitHub team membership — only legitimate possession of a webhook secret for *some* organization served by the same Shipit instance, which by design several distinct, mutually untrusted GitHub organizations may each hold. The attack is a single crafted HTTP POST with a correctly computed HMAC.

### Recommendation
After signature verification succeeds for organization `X`, every handler must independently verify that the repository/commit/stack being mutated actually belongs to organization `X` (i.e., that `repository.full_name.split('/').first == repository_owner`, or equivalently scope `Repository.from_github_repo_name` lookups and `Commit.where(sha:)` lookups by the authenticated organization) before performing any write. `StatusHandler` in particular needs to scope its `Commit` lookup by owning organization rather than by bare SHA.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (supported per `lib/shipit/github_app.rb`).
2. As an administrator with legitimate access to `OrgA`'s webhook secret only, compute `sha1=HMAC(OrgA_secret, body)` for a hand-crafted push payload where:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: 'OrgA')`, and the signature verifies successfully.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('OrgB/victim-repo')`, matching `OrgB`'s stack, and calls `stack.sync_github(expected_head_sha: params.after)` — mutating `OrgB`'s stack state despite the request only having been authenticated for `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
