### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while the acted-upon repository is taken from the unrelated `repository.full_name` field, enabling cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **unverified** JSON body, and only checks that the raw body's signature matches *that org's* secret. [1](#0-0) [2](#0-1) 

Every downstream handler, however, resolves the actual `Stack`/`Repository` to act on using a completely different field of the same body: `repository.full_name`. [3](#0-2) 

Because the signature only proves "this HMAC key holder can construct this exact byte-for-byte payload," and not "the `owner.login` field is consistent with `full_name`," the field used for authorization (`owner.login`) and the field used for the actual write-effect (`full_name`) are never cross-checked against each other.

### Finding Description
In a multi-organization Shipit deployment (`secrets.github` keyed by org, see `Shipit.github(organization:)` / `Shipit.github_app_config`) each tenant organization has its own `webhook_secret` configured independently in `GitHubApp`. [4](#0-3) [5](#0-4) 

The controller's trust decision is:
```
github_app = Shipit.github(organization: repository_owner)   # keyed off body["repository"]["owner"]["login"]
verified = github_app.verify_webhook_signature(sig, raw_post)  # HMAC over the WHOLE raw body, with THAT org's secret
``` [6](#0-5) 

This only proves the request was HMAC-signed by whoever holds organization `X`'s `webhook_secret` (a value any admin of organization `X`'s GitHub repo/org can view/rotate on GitHub's side, since it is simply the shared webhook secret configured when the org owner sets up their GitHub webhook to point at this Shipit instance — no Shipit session, `ApiClient` token, or Shipit-side privilege is required). It proves nothing about which repository the payload's `repository.full_name` claims to describe.

Once past `verify_signature`, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers that use `payload.dig('repository', 'full_name')` to look up the `Repository`/`Stack` to mutate: [7](#0-6) [3](#0-2) 

`PushHandler`, for example, uses this repository lookup to fetch matching, non-archived stacks and force a GitHub sync to an attacker-chosen SHA: [8](#0-7) 

So the binding actually enforced is: `organization whose secret signed the bytes == repository.owner.login (attacker-controlled field)`, while the binding that should hold for safety is `organization whose secret signed the bytes == organization that owns repository.full_name (the repo actually written to)`. These are never checked to be equal. An attacker who administers/controls the webhook configuration for organization A (a legitimate, low-privilege tenant of the same shared Shipit instance) can sign an arbitrary JSON body with A's secret while setting `repository.full_name` to `"victim-org/victim-repo"` and `repository.owner.login`/`organization.login` to `"A"`. The controller validates the signature against A's secret (which matches, since the attacker crafted and signed the exact bytes), then the handler acts on `victim-org/victim-repo` using the value from `full_name`, which was never covered by any equality check against the verified organization.

### Impact Explanation
This is not merely a webhook-spoofing curiosity confined to the attacker's own org — it is a cross-repository/cross-organization trust break, matching the "High: escalation... unauthenticated read of stack state... " and, depending on which event/handler is abused, potentially "unauthorized deploy" class impact:
- `push` events let the attacker force `Stack#sync_github(expected_head_sha:)` on a victim organization's stack, syncing an attacker-chosen commit SHA into the victim's deploy pipeline state.
- `status`/`check_suite`/`membership`/`pull_request` events (all dispatched the same unchecked way) let the attacker inject commit statuses, check-run refreshes, or PR/merge-request state transitions against a repository the attacker's org has no legitimate relationship with, as long as the victim repo is also configured in the same Shipit instance.

The severity depends on which handler is reached, but the underlying defect — authorizing against one payload field while acting on another, unrelated payload field, with no consistency check tying them together — is the same class of flaw as the Sherlock report's "verified something but acted on an unverified/uncovered amount," just instantiated as "verified organization identity but acted on unverified repository identity."

### Likelihood Explanation
Requires only that the attacker control (or know the `webhook_secret` of) some organization already configured in this Shipit instance's multi-org `secrets.github` — a routine, low-privilege capability for any tenant org admin, not a Shipit account, `ApiClient` token, or GitHub App key. No repository write access to the victim's GitHub repo, no Shipit login, and no interception is needed. This is realistically exploitable in any Shipit deployment serving more than one GitHub organization from a shared instance.

### Recommendation
After signature verification, additionally verify that `repository.owner.login` (the org whose secret validated the signature) matches the owner segment of `repository.full_name` before dispatching to handlers, e.g. reject the request if `payload.dig('repository', 'full_name')&.split('/')&.first != repository_owner`. More robustly, look up the `Repository`/`Stack` by `full_name` first, derive its actual owning organization from Shipit's own configuration, and verify the signature using that organization's secret rather than trusting an attacker-suppliable field to pick the verification key.

### Proof of Concept
1. Shipit is configured with `secrets.github: { "attacker-org" => { webhook_secret: "S_A" }, "victim-org" => { webhook_secret: "S_V" } }`, both orgs' repos are tracked as Shipit stacks.
2. Attacker crafts body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` (they legitimately know `S_A`, their own org's secret) and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner == "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature against `S_A` over the exact bytes sent. [6](#0-5) 
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (from the unrelated `full_name` field) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack. [9](#0-8) [10](#0-9) 

The victim's stack state is mutated using only the attacker's own organization's webhook secret — no credential or repository access belonging to `victim-org` was ever required.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
