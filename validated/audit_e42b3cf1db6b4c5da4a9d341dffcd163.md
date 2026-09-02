### Title
Webhook signing organization not bound to the repository acted upon, enabling cross-organization state writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-tenant deployments (Shipit officially supports configuring one `GitHubApp`/`webhook_secret` per GitHub organization, see `docs/setup.md` "Using Multiple Github Applications"), `WebhooksController#verify_signature` picks the HMAC secret to check against using `repository.owner.login` (or `organization.login`) pulled from the untrusted JSON body, while the downstream event handlers resolve the `Stack`/`Repository` to act on using a *different* field of that same body, `repository.full_name`. Nothing enforces that the organization whose secret validated the signature is the same organization that owns the repository the handler subsequently mutates. This reproduces the GHSA-qvwc-hc2r-82qv bug class: a signature that authenticates one identity (the signing organization) is relied upon to authorize action on a different, attacker-chosen identity (the target repository/organization) referenced in an unauthenticated part of the trust decision.

### Finding Description
`verify_signature` selects the app/secret purely from the payload: [1](#0-0) [2](#0-1) 

The HMAC check itself is a keyed hash over the entire raw body using the secret configured for that `repository_owner`/organization: [3](#0-2) 

This proves only that *whoever crafted this exact payload knows the shared secret configured for the organization named in `repository.owner.login`* — it says nothing about which repository the payload's other fields claim to describe. Downstream, `Webhooks::Handlers::Handler#stacks` resolves the target purely from `repository.full_name`, a sibling field inside the same body, independent of `repository.owner.login`: [4](#0-3) 

Concrete write path: `PullRequest::ClosedHandler` resolves `Repository.from_github_repo_name(params.repository.full_name)` and calls `review_stack.archive!` on it: [5](#0-4) 

The equality that is supposed to hold — `organization whose webhook_secret validated the signature == organization that owns the repository being mutated` — is never checked. An attacker who legitimately controls a GitHub App installation for *their own* organization (a valid, low-privilege tenant of a shared multi-org Shipit instance) can sign an arbitrary payload with their own real `webhook_secret`, set `repository.owner.login`/`organization.login` to their own org (so `verify_signature` passes), but set `repository.full_name` to `victim-org/victim-repo`. `WebhooksController#create` then dispatches this to the real handler for `victim-org/victim-repo`, whose `Repository`/`Stack` objects it does not control.

### Impact Explanation
This breaks the binding "organization authenticated by the webhook signature == repository/organization written by the handler," letting an attacker with only their own org's webhook secret trigger state changes on another organization's `Repository`/`Stack`/`ReviewStack` records that Shipit manages — a cross-organization write. Concretely, forged `pull_request` `closed` events can archive a victim organization's review stacks, forged `push` events can force resync attempts against a victim `Stack`, and other handlers keyed the same way (`opened`, `labeled`, `check_suite`, `status`) can similarly act on repositories the attacker's signing organization does not own. This fits the "cross-repository writes" Critical bucket in scope, even though the specific example demonstrated (archiving) is a lower-value write than a deploy/merge — the root cause equally affects any handler that trusts `repository.full_name` after verifying against `repository.owner.login`.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple GitHub organizations (an explicitly documented, supported deployment mode), and (2) the attacker controls a legitimate GitHub App installation/webhook secret for at least one of the configured organizations (a normal, low-privilege tenant, not a Shipit account or API token). No repository write access, TLS interception, or session is required — only the ability to send an HTTP POST to `/webhooks` with a validly-HMAC'd body for the attacker's own org. This is a realistic scenario for any shared, multi-org Shipit installation.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, after resolving the signing organization, verify that the resolved `Repository`/`Stack` for `repository.full_name` actually belongs to that same signing organization (e.g., compare `repository.full_name.split('/').first` against `repository_owner`) before dispatching to any handler, rejecting the event otherwise.

### Proof of Concept
1. Configure Shipit for two orgs, `attacker-org` (attacker administers the GitHub App, knows its `webhook_secret`) and `victim-org` (has a Shipit `Stack`/`ReviewStack` the attacker cannot access).
2. Attacker crafts a `pull_request` webhook JSON body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "...": "..." },
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } },
  "sender": { "login": "attacker" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and validates successfully since the attacker used their own real secret. [1](#0-0) 
5. `Shipit::Webhooks.for_event('pull_request')` dispatches to `PullRequest::ClosedHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `review_stack.archive!` — a write on `victim-org`'s data performed using only `attacker-org`'s credentials. [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
