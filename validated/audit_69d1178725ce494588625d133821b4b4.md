### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while every event handler acts on `repository.full_name` from the same unverified JSON body - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on a field (`repository.owner.login`, falling back to `organization.login`) taken directly from the untrusted, attacker-supplied JSON body, before that body's authenticity has been established. Every `Shipit::Webhooks::Handlers::Handler` subclass then resolves the actual target repository/stack using a *different* field from the very same body — `payload.dig('repository', 'full_name')`. The equality the code implicitly assumes, `organization authenticated == repository written`, is never enforced.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` runs `verify_signature` as a `before_action`: [1](#0-0) 

`repository_owner` is computed purely from the request body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the `GitHubApp` instance (and thus the `webhook_secret`) tied to *that* organization, and the signature is checked with `github_app.verify_webhook_signature(header, request.raw_post)`, defined in `lib/shipit/github_app.rb`: [3](#0-2) 

Once verification succeeds, `create` dispatches the entire raw body to the handlers for the event: [4](#0-3) 

Every handler, however, resolves the repository/stack to mutate using a completely different key from that same body: [5](#0-4) 

For example `PushHandler` finds stacks by that `full_name` and calls `stack.sync_github`: [6](#0-5) 

and `StatusHandler` writes a commit status onto commits matched purely by `sha`, with no repository check at all: [7](#0-6) 

Because Shipit supports multiple configured GitHub organizations, each with its own `webhook_secret` (`lib/shipit/github_app.rb` initializer reads `@webhook_secret = @config[:webhook_secret]`), an actor who legitimately administers *any one* configured organization — and therefore knows that organization's own webhook secret — can send `POST /webhooks` with:
- `X-Github-Event: status` (or `push`)
- `repository.owner.login` / `organization.login` = their own organization (so `verify_signature` picks their own `webhook_secret` and the HMAC they compute with it passes)
- `repository.full_name`, `sha`, and other payload fields referencing a **different**, victim-owned stack/commit that they do not control

`verify_signature` only proves "this body was signed with organization X's secret"; it never proves "this body's `repository.full_name` belongs to organization X." The handler layer trusts `repository.full_name`/`sha` unconditionally. This breaks the intended binding: *organization that authenticated == repository that is written*.

### Impact Explanation
Using the `status` event, an attacker who administers one onboarded GitHub organization (any Shipit tenant, not the victim's) can forge a passing `X-Hub-Signature` for their own secret while setting `sha` to a commit belonging to a victim's stack, and inject an arbitrary `state`/`context`/`description` commit status via `Commit#create_status_from_github!`. Shipit stacks use commit statuses (`required_statuses`, CI-based gating, `deployable?`) to decide whether a commit is eligible for deploy/merge. Forging a "success" status for a required CI context on a victim commit can make an otherwise CI-failing or unreviewed commit appear deployable, enabling an **unauthorized deploy** through the normal deploy path once a legitimate user (or continuous-deployment) picks it up. Using the `push` event with a forged victim `repository.full_name`, the attacker can also force `GithubSyncJob`/`sync_github` to run against a victim stack, and other handlers keyed on `repository.full_name` (pull request handlers, review-stack provisioning/archival) are similarly reachable across organizational boundaries. This crosses the "escalation into authorization" / "unauthorized deploy" bar without requiring a Shipit session, `ApiClient` token, or the victim's `webhook_secret`.

### Likelihood Explanation
Requires only that the attacker be an authenticated administrator of *some* GitHub organization that has been separately onboarded into the same Shipit instance (a common multi-tenant deployment), and that they know their own org's `webhook_secret` (which they configured themselves) — no access to the victim org, its secret, or any Shipit credential is needed. Constructing the forged JSON body and signature is a simple HTTP POST. Likelihood is moderate: it depends on the deployment hosting more than one organization/repository owner and on that fact being knowable/exploitable by a party who isn't the victim, but no privileged access is required beyond legitimate administration of one tenant.

### Recommendation
After signature verification, re-derive the authorized organization from the verified GitHub App/organization context (not from `repository_owner` computed pre-verification) and explicitly assert that `payload.dig('repository','owner','login')` used for signature selection is equal to (or a subset of) the organization that owns the `repository.full_name`/`sha` the handler is about to act on. Reject the webhook (`head :unprocessable_entity`) if the signing organization does not match the repository being referenced by the payload, rather than implicitly trusting cross-referenced but independently-controlled fields of the same unverified body.

### Proof of Concept
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC-SHA1 computed with attacker-org's own configured webhook_secret over the raw body below>

{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
  "sha": "<sha of a commit belonging to victim-org/victim-repo tracked by Shipit>",
  "state": "success",
  "context": "required-ci-check",
  "description": "forged",
  "created_at": "2026-01-01T00:00:00Z"
}
```
`verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `GitHubApp`, and the HMAC (computed by the attacker with a secret they legitimately know) validates. `WebhooksController#create` then dispatches to `StatusHandler`, which matches `Commit.where(sha: params.sha)` — the victim's commit — and calls `create_status_from_github!`, writing an attacker-controlled CI status onto a commit the attacker does not own, with no cross-check against `attacker-org`. [8](#0-7) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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
