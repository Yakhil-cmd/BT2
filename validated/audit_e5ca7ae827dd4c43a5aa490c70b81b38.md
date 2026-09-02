### Title
Webhook signature verification is bypassed for organizations without a `webhook_secret`, letting `StatusHandler` forge deployability-affecting commit statuses across every stack in the instance - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects a `GitHubApp` based on `repository_owner` and asks it to verify the HMAC signature. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that organization. Independently, `StatusHandler#process` does not scope by repository at all: it matches `Commit.where(sha: params.sha)` across the *entire* Shipit database and calls `create_status_from_github!` on every match. The field that gates trust (`repository_owner`, used only to pick which secret verifies the request) is never bound to the field that is acted upon (`sha`, resolved globally with no ownership check). Where any organization configured in the instance has no `webhook_secret` (documented as "optional" in `docs/setup.md`), this reduces to a fully unauthenticated write path that can set commit statuses — which drive CI-gating and continuous delivery — for any stack in the instance, not just the org whose name was used in the payload.

### Finding Description
`WebhooksController#verify_signature` picks the signer purely from an attacker-controlled field: [1](#0-0) [2](#0-1) 

The chosen `GitHubApp` treats a missing `webhook_secret` as automatically verified: [3](#0-2) 

`webhook_secret` is explicitly documented as optional per organization: [4](#0-3) 

Once past this gate, `StatusHandler#process` resolves the target purely by commit SHA, with no reference to `repository` at all (unlike `Handler#stacks`, which other handlers use to scope by `repository.full_name`): [5](#0-4) [6](#0-5) 

The resulting `Status` record has side effects that influence deploy eligibility for the owning stack: it enables CI on the stack and schedules continuous delivery evaluation as soon as it is created: [7](#0-6) [8](#0-7) 

The equality the code should enforce, but does not, is:
`organization verified by signature == organization owning the stack whose commit status is being written`.
Instead, `verify_signature` checks `repository_owner == <org resolved from payload>`, while `StatusHandler` checks nothing beyond `sha == params.sha`, which is a completely different, globally-scoped key with no tie back to the verified organization.

### Impact Explanation
If any organization/app registered in a multi-tenant Shipit deployment is configured without a `webhook_secret` (a supported, documented configuration), an attacker can send a crafted `status` event whose `repository.owner.login`/`organization.login` names that unsecured org, causing `verify_webhook_signature` to return `true` unconditionally, with no signature required at all. The payload's `sha` can then reference a commit belonging to any other stack in the instance. `StatusHandler` will create a fabricated `success` status for that commit, which can satisfy `ci.require`/`ci.blocking` contexts and trigger `schedule_continuous_delivery`, potentially causing an **unauthorized deploy** of a commit that never actually passed CI, for a repository/organization the attacker has no legitimate relationship to. This crosses the exact boundary flagged as in-scope: "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Exploitability depends on at least one organization in the deployment having an unset `webhook_secret` — an explicitly supported, documented configuration, not a host-app misconfiguration outside the engine's control. Organization names are typically public (GitHub org slugs), and commit SHAs of a target repository are also public via the GitHub API/UI, so the two pieces of information an attacker needs (an unsecured org name, and a target SHA) are both obtainable without any privileged access, session, or token.

### Recommendation
- `StatusHandler` (and any other handler that doesn't already do so) must resolve the affected `Commit`/`Stack` strictly within the repository indicated by the payload's `repository.full_name`, matching how `PushHandler` and the PR handlers use `Handler#stacks`/`Repository.from_github_repo_name`, rather than querying `Commit` globally by `sha`.
- `verify_signature` should bind the verified organization to the repository actually referenced by the event payload before any handler processes it, and reject events where these do not match.
- `GitHubApp#verify_webhook_signature` should not silently return `true` when `webhook_secret` is blank; either require a secret for every configured organization, or make the auto-pass behavior explicit/opt-in with a loud warning, since it currently makes signature verification a no-op for any org that omits the (documented as "optional") secret.

### Proof of Concept
1. Deployment configures two orgs: `victim-org` (with a `webhook_secret`, owns `Stack A` with CI-gated continuous delivery) and `attacker-org` (registered but left with `webhook_secret: nil`, as permitted by `docs/setup.md`).
2. Attacker discovers, via GitHub's public API, the SHA of a commit on `victim-org`'s repository that is pending/failing CI on `Stack A`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and no (or an arbitrary) `X-Hub-Signature`, and body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}},
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-context"
}
```
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking anything.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim commit, and calls `commit.create_status_from_github!(params)`, creating a fabricated `success` status for `Stack A`'s commit — which can flip `deployable?` and trigger `schedule_continuous_delivery`, resulting in an unauthorized deploy.

Note: I could not fully trace whether every deployed configuration in practice always sets `webhook_secret` for all orgs (that is an operator choice outside this repo), so the concrete exploitability in any specific production instance depends on that configuration; the code-level gap (auto-pass on blank secret, plus unscoped `StatusHandler`) is confirmed directly from the cited source.

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L38-44)
```ruby
    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
