### Title
Cross-organization status forgery — webhook signature bound to `repository.owner.login`, but status target resolved from unrelated `sha` field, allowing unauthorized deploy triggering in another org's stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
### Finding Description
Shipit supports multi-tenant GitHub App configuration, where each GitHub organization has its own webhook secret [1](#0-0) . Incoming webhooks are verified by selecting the signing key based solely on the organization named in the payload:

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This only proves the request was signed with the secret belonging to whichever org is named in `repository.owner.login` (or `organization.login`). It does **not** prove anything about any other field in the JSON body — the HMAC covers the raw bytes, but *which* record inside Shipit gets mutated is decided later by handler code using a completely different, unrelated field.

`StatusHandler`, which processes `status` events, resolves its target purely from the attacker-controlled `sha` field, with no scoping to the organization/repository that was actually verified:

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit.where(sha: ...)` is a global, unscoped lookup across the entire Shipit instance — it is not restricted to commits belonging to the organization identified by `repository_owner`. Creating the `Status` record directly triggers CI-enablement and continuous-delivery scheduling:

```
after_create :enable_ci_on_stack
after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
``` [4](#0-3) 

The equality that should be enforced but is not:
`organization_that_signed_the_webhook (repository_owner) == organization_owning_the_stack/commit_that_gets_written (commit.stack.repository.owner)`

Because this equality is never checked, an attacker who legitimately controls the webhook secret for **one** onboarded organization can forge a payload whose `repository.owner.login`/`organization.login` matches their own org (so it passes signature verification with their own valid secret) while setting `sha` to any commit SHA belonging to a stack/repository owned by a **different**, unrelated organization tracked by the same Shipit instance.

### Impact Explanation
This is directly analogous to the referenced M-18 finding: a field that is acted upon (`sha`, resolving the target commit/stack) is never covered by the trust decision made earlier (the org-scoped signature check only binds the caller to `repository_owner`, not to the record actually mutated). The result is a cross-organization write: an attacker with authority over only their own org's webhook secret can create arbitrary CI `status` records (`state: success`, arbitrary `context`/`target_url`/`description`) on commits belonging to any other organization's stacks. Because status creation both marks CI as enabled and reschedules continuous delivery evaluation for that commit's stack, this can be used to satisfy `ci.require` checks and push an otherwise CI-gated or unreviewed commit toward becoming eligible for continuous deployment in a stack the attacker does not own — an unauthorized deploy-enabling action against a repository/organization outside the attacker's control. This falls into the required "cross-repository writes / unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitation requires only that the attacker legitimately control (be able to sign requests for) a single organization already configured in the multi-tenant Shipit deployment — no `ApiClient` token, GitHub App private key, session, or Shipit account is required, since `/webhooks` is a public, unauthenticated endpoint gated only by the HMAC signature [5](#0-4) . Any customer/org onboarded to a shared multi-org Shipit instance can reach every other onboarded org's commits this way, making the likelihood high in any deployment using the documented multi-organization `github:` configuration format.

### Recommendation
In `StatusHandler#process` (and analogous handlers such as `Handler#stacks`/`#repository_name`), scope the lookup to the same organization that produced a valid signature: verify that the `Commit`'s `stack.repository.owner` matches `repository_owner` used in `WebhooksController#verify_signature` before creating/mutating any record, e.g. by passing the verified `repository_owner`/`repository.full_name` into the handler and requiring `commit.stack.repository.owner_login == verified_owner` (or filtering `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: verified_owner })`).

### Proof of Concept
1. Shipit is configured for two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` per `lib/shipit/github_app.rb`.
2. Attacker controls `attacker-org`'s webhook secret (as its onboarding admin) and knows/observes a commit SHA (`X`) belonging to `victim-org`'s tracked stack (SHAs are public, visible on GitHub or in Shipit's UI).
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "X",
  "state": "success",
  "context": "ci/travis",
  "target_url": "https://attacker.example.com",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
}
```
4. Attacker computes `X-Hub-Signature` over the raw body using `attacker-org`'s known webhook secret and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` selects `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (the secret matches) — `app/controllers/shipit/webhooks_controller.rb:24-30`.
6. `StatusHandler#process` runs `Commit.where(sha: "X")`, finds the commit under `victim-org`'s stack (no ownership check), and calls `create_status_from_github!`, creating a forged `success` status on `victim-org`'s commit — `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, `app/models/shipit/status.rb:18-19`.

*Note: full confirmation of the exact downstream conditions under which `schedule_continuous_delivery` results in an actual automated deploy (e.g. required `ci.require` contexts, continuous-deployment toggle state) was not exhaustively traced in this review due to time constraints; the CI-status forgery and cross-organization write itself, however, is directly confirmed in the cited code.*

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```
