### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, not to the `repository.full_name` the handlers act on, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The externally reported bug is a canonicalization/binding flaw: a value used to compute a cryptographic commitment (the MiMC hash) does not actually commit to all the semantically relevant bytes of the input, so two different inputs are treated as equivalent by the verifier. The same class of bug exists in `Shipit::WebhooksController`: the field used to pick *which organization's secret* authenticates an inbound webhook (`repository.owner.login` / `organization.login`) is not the same field the event handlers use to decide *which repository/stack is mutated* (`repository.full_name`). Both fields live in the same attacker-influenced JSON body, but nothing binds them together, so a signature valid for organization A can be replayed to act on a repository belonging to organization B.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization configuration solely from `repository_owner`, derived from the JSON body: [1](#0-0) [2](#0-1) 

It then verifies the HMAC in `X-Hub-Signature` against that organization's `webhook_secret`: [3](#0-2) 

Once verification passes, `WebhooksController#create` hands the *entire raw JSON body* to the registered handlers for the event, without re-checking that the body's repository actually belongs to the organization whose secret authenticated it: [4](#0-3) 

Every handler, however, resolves the target `Repository`/`Stack` using a *different* field of the same body — `repository.full_name` — with no cross-check against `repository.owner.login`: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` splits `full_name` on `/` and does an independent `owner`/`name` lookup, again decoupled from the value used for signature routing: [7](#0-6) 

This is exactly the collision pattern in the report: the check that is supposed to bind the message to its context (owner.login → secret) and the value that is actually acted upon (full_name → mutated stack/repository) are computed from independent sub-fields of a single unauthenticated JSON blob. The HMAC covers the raw bytes of the whole body, but `verify_webhook_signature` never asserts that `owner.login` and the owner portion of `full_name` refer to the same repository — the binding "organization authenticated == repository written" is never enforced.

### Impact Explanation
Any actor who legitimately controls a webhook secret for one organization/repository configured in this Shipit instance (i.e., someone who created that webhook in GitHub themselves and therefore knows the secret value they typed in) can craft an arbitrary JSON body where:
- `repository.owner.login` (or `organization.login`) = their own organization, so `verify_signature` selects their known secret and the HMAC check passes, and
- `repository.full_name` = any other org/repo configured as a `Shipit::Repository` in the same instance.

Because the handlers key exclusively off `full_name`, this forged, self-signed payload is processed as if it came from the victim repository. Depending on event type this yields:
- `status` events: writing forged commit-status rows (`Handlers::StatusHandler`) against commits in an unrelated repository/stack, which can influence Shipit's merge/deploy gating logic (cross-repository write, potential unauthorized deploy).
- `push`/`check_suite` events: triggering `GithubSyncJob`/`RefreshCheckRunsJob` against an arbitrary stack the attacker does not own.
- `pull_request` events: archiving/unarchiving or otherwise mutating review stacks belonging to a repository the attacker has no access to.

This crosses the "cross-repository writes" / "unauthorized deploy" bar because it lets an attacker who only controls their own org's webhook secret mutate state belonging to a different, unrelated organization's stack.

### Likelihood Explanation
Requires the attacker to control at least one legitimate webhook configuration (their own organization's secret) already onboarded to the Shipit instance — a realistic scenario for any multi-tenant or multi-org Shipit deployment, since organization onboarding is routine and the attacker never needs credentials belonging to the victim organization. Constructing the forged JSON body and computing its HMAC with their own known secret requires no special access beyond that.

### Recommendation
After `verify_signature` succeeds, re-derive the organization from the same field the handlers use to select the target (`repository.full_name`'s owner segment, or `organization.login` for org-scoped events) and require it to match the organization whose secret validated the signature. Reject the request if `repository.owner.login`/`organization.login` disagrees with the owner segment of `repository.full_name`. Equivalently, look up the `Repository`/`Stack` first, obtain its own configured `github_app`/secret, and verify the signature against that specific stack's secret rather than a secret selected from an unauthenticated field of the same payload.

### Proof of Concept
1. Attacker legitimately configures webhook `X-Hub-Signature` secret `S` for their own org `attacker-org` (visible to them in GitHub's webhook settings).
2. Attacker crafts payload:
```json
{
  "action": "push",
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `sha1=HMAC(S, body)` and sends `POST /webhooks` with header `X-Hub-Signature: sha1=<computed>` and `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `webhook_secret` = `S`, and the HMAC matches — request passes verification (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`; `lib/shipit/github_app.rb:76-83`).
5. `Shipit::Webhooks::Handlers::PushHandler` then resolves `stacks` via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and enqueues a sync/action against `victim-org`'s stack — despite the signature never having been validated against `victim-org`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
