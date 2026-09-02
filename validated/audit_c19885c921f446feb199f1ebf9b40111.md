### Title
Webhook signature is bound to organization, but event handlers act on unrelated payload fields (repository / commit sha) — cross-repository status/state forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` proves only that the raw request body was signed with the webhook secret belonging to *one specific GitHub organization* — the organization derived from `repository.owner.login` (or the `organization.login` fallback). It does not bind that verified organization to the specific repository or commit the event handlers subsequently act on. Several handlers act on other payload fields (`repository.full_name`, or in the case of `StatusHandler`, a bare commit `sha` with no repository scoping at all) that are never covered by the organization-to-secret binding. An attacker who legitimately controls (or has been granted webhook admin rights on) any single GitHub organization configured in this Shipit instance can therefore forge a validly-signed webhook whose payload references a repository, stack, or commit belonging to a completely different organization, and have Shipit process it as authentic.

### Finding Description
`verify_signature` selects which organization's `webhook_secret` to validate against using only `repository.owner.login`/`organization.login`: [1](#0-0) [2](#0-1) 

This produces a binding: *"organization that authenticated" = repository.owner.login field in the payload*. However, that equality is never enforced against the field(s) the handlers subsequently mutate state from:

- `Handler#repository_name` (used by `PushHandler` and others) resolves the acted-upon repository from `payload.dig('repository', 'full_name')` — a separate, independently-controlled JSON field from `repository.owner.login`: [3](#0-2) 

- `StatusHandler` goes further and performs **no repository scoping whatsoever** — it looks up commits purely by `sha` across the entire instance and writes a GitHub-reported CI status onto them: [4](#0-3) 

Since `Shipit.github(organization: repository_owner)` selects a **per-organization** `webhook_secret` (multiple GitHub orgs/apps can be configured, each with its own secret): [5](#0-4) [6](#0-5) 

...an attacker who is a legitimate admin of *any* organization that has its own webhook secret configured in this Shipit instance can:
1. Craft a JSON body whose `repository.owner.login` (or `organization.login`) is their own org — so `verify_signature` fetches *their* known secret and the HMAC check passes.
2. Set every other unrelated field — `repository.full_name` for `PushHandler`/`PullRequest` handlers, or simply `sha` for `StatusHandler` — to reference a target belonging to an entirely different, victim organization/stack tracked by the same Shipit instance.
3. Submit the forged, validly-signed payload to `/webhooks`.

Because the signature only proves "signed by organization X's secret" and never proves "this payload's repository/commit belongs to organization X", the request is accepted and processed against the victim's data. This exactly mirrors the reported bug class: a security-relevant flag/binding (`removingAllLiquidity` in the original report; here, "which org is authorized") is computed from one piece of state while the code that consumes it operates on a different, unverified piece of state (`orderInfo.liquidityTotal` after mutation in the report; here, `repository.full_name`/`sha` instead of `repository.owner.login`).

### Impact Explanation
- `StatusHandler` allows an attacker to write arbitrary GitHub commit statuses (`state`, `context`, `description`, `target_url`) onto **any** commit tracked by the Shipit instance, regardless of which organization owns it, as long as the attacker knows the commit sha (trivially available for any public repository, or observable through the target stack's own commit history in Shipit's UI). Forged `success` statuses for `ci.require` contexts can satisfy `Commit#deployable?`-style CI gating, enabling an **unauthorized deploy** of a commit that never actually passed CI/review — a Critical-impact outcome explicitly listed as in-scope ("an unauthorized deploy, rollback or merge").
- `PushHandler` and the `PullRequest::*` handlers resolve their target via `repository.full_name`, unrelated to the organization used for signature verification, enabling **cross-repository writes**: forcing `GithubSyncJob` execution or archiving/unarchiving/creating review stacks for a victim organization's repository using a signature computed with the attacker's own, unrelated organization secret.

### Likelihood Explanation
Exploitation requires only: (a) the attacker administers/knows the webhook secret of *any single* GitHub organization already configured in the target Shipit deployment (a normal, non-privileged position relative to that other organization's stacks), and (b) knowledge of a target commit sha or repository full name, both of which are typically public or discoverable via the Shipit UI/API itself. No Shipit session, `ApiClient` token, or GitHub App private key is required — only an organization-scoped `webhook_secret`, which is a materially weaker credential than the ones excluded by the rules (it does not grant any privilege over the *victim* repository).

### Recommendation
- In `WebhooksController#verify_signature`, after computing `repository_owner`, cross-check that every repository-identifying field consumed downstream (`repository.full_name`, `organization.login`) is consistent with `repository_owner`, rejecting the request otherwise.
- In `Handler#repository_name` and `StatusHandler#process`, scope lookups by the repository that was actually verified (i.e., require and use the same `repository.owner.login`/`organization.login` used during signature verification), instead of trusting `repository.full_name` or bare `sha` independently.
- Consider deriving a canonical "authenticated repository" object once in the controller and passing it explicitly into each handler, rather than letting handlers re-derive it from unrelated payload fields.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `attacker-org` (attacker is an admin, knows its `webhook_secret`) and `victim-org` (tracks a sensitive stack, e.g. `victim-org/prod-app`).
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha, e.g. from public GitHub history>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s secret, and the HMAC matches → request accepted.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, writing a forged `success` status onto the victim commit in `victim-org/prod-app`, with no relation to `attacker-org` ever checked. [7](#0-6)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
  end
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
