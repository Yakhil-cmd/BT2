### Title
Webhook signature is bound to the payload's organization/repository-owner, not to the repository the event handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a delivery against using `repository_owner`, computed from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). This value is only used to *pick the HMAC key*; it is never checked against the fields that individual event handlers actually use to decide *which stack/commit/repository* to mutate.

### Finding Description
`verify_signature` does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 
with
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

The verification only proves "this raw body was signed by the app configured for `repository_owner`". It does not bind the signature to any specific target repository. Once verification passes, the full raw JSON body is dispatched unmodified to handlers:
```
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [3](#0-2) 

Handlers derive the actual target from a *different* field, `repository.full_name`, e.g. the base `Handler#repository_name`:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 
which `stacks` resolves via `Repository.from_github_repo_name(repository_name)` [5](#0-4) , and is used verbatim by `PushHandler#process` [6](#0-5)  and every `PullRequest::*Handler#repository`.

Even more directly, `StatusHandler#process` does not consult repository/owner at all — it matches purely on commit SHA across the entire installation:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [7](#0-6) 

This is the same bug class as the report: a field that is *acted upon* (`repository.full_name` / commit `sha`, which select which repository/stack/commit gets mutated) is never covered by the value the signature check actually authenticates (`repository.owner.login`/`organization.login`, which only selects the HMAC secret). The binding that should hold — "the organization whose secret authenticated this delivery" == "the repository the handler writes to" — is broken.

**Attacker model:** This engine explicitly supports multiple, independently configured GitHub Apps, one per organization, each with its own `webhook_secret` (see `Shipit.github(organization:)`, `test/dummy/config/secrets_double_github_app.yml`, `lib/shipit/github_app.rb`). [8](#0-7)  An organization admin who legitimately owns and configures one such GitHub App (a normal, unprivileged tenant of this shared Shipit instance, with no Shipit session, no `ApiClient` token, and no access to any other org's repos) controls that app's `webhook_secret` value. Nothing in `verify_webhook_signature` [9](#0-8)  ties the computed signature to any specific repository under that organization — it is a plain HMAC-SHA1 over the raw body using the org-level secret. That attacker can therefore compute a fully valid `X-Hub-Signature` for an arbitrary POST body (setting `repository.owner.login`/`organization.login` to their own org so `repository_owner` selects the app whose secret they know) while setting `repository.full_name` (for push/pull_request/check_suite handlers) or `sha` (for the status handler) to point at a completely different, victim organization's stack/commit tracked by the same Shipit instance.

### Impact Explanation
Using `status` events, the attacker can inject arbitrary GitHub commit statuses (state, context, description, target_url) for any commit SHA hosted anywhere on the Shipit instance, since `StatusHandler` looks the commit up globally with no repository/owner check [7](#0-6) . Commit status directly feeds `Commit#deployable?`:
```
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [10](#0-9) 
and `success?`/`blocked?` are computed purely from these injected statuses; `deployable?` in turn gates `schedule_continuous_delivery` [11](#0-10)  and merge-queue scheduling (`stack.schedule_merges`) [12](#0-11) . Forging a "success" status on a victim commit that never actually passed CI can trigger an unauthorized continuous deploy or unblock the merge queue on a completely unrelated organization's stack. This satisfies the "unauthorized deploy, rollback, or merge" Critical bar.

`push` events can also be forged cross-organization to force `GithubSyncJob` re-sync on another org's stack, and `pull_request`/`check_suite` handlers can be made to archive/unarchive review stacks or update PR state on a victim's repository — all Critical-adjacent cross-repository writes triggered without any credential belonging to the victim organization.

### Likelihood Explanation
Requires: (1) the Shipit deployment to be multi-tenant with more than one configured GitHub App/organization (a supported, documented configuration — see `docs/setup.md` and the `secrets_double_github_app.yml` fixture), and (2) attacker knowledge of one org's `webhook_secret`, which any admin of that org's own GitHub App legitimately possesses. No Shipit account, API token, or GitHub OAuth session is required — only the ability to send an arbitrary HTTP POST to the shared `/webhooks` endpoint. Likelihood is Medium: it is not exploitable against single-tenant installs, but is fully self-serve for any tenant of a shared instance.

### Recommendation
Bind the verified signature to the specific repository the payload claims to act on, not merely to the organization/app used to pick the HMAC key:
- After signature verification, re-derive `repository.owner.login`/`organization.login` and cross-check it against `repository.full_name`'s owner (and, for `status` events, resolve the commit's stack/repository and confirm its owning organization matches the authenticated organization) before invoking handlers.
- In `Shipit::Webhooks::Handlers::Handler#stacks` and `StatusHandler#process`, scope lookups to repositories owned by the authenticated organization, rejecting/logging events where `repository.full_name`'s owner segment differs from the app/organization that produced a valid signature.

### Proof of Concept
Given a Shipit instance configured with two orgs, `attacker-org` (attacker-controlled GitHub App, known `webhook_secret_A`) and `victim-org` (tracks stack `victim-org/victim-repo`, commit `deadbeef...`):

1. Attacker builds a JSON body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_A, body)` — a value they can legitimately produce since they own `attacker-org`'s app.
3. POST to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s app, and the signature check succeeds [1](#0-0) .
5. `StatusHandler#process` matches `Commit.where(sha: "deadbeef...")` — the victim's commit — and creates a forged "success" status on it [7](#0-6) , potentially making `victim-org/victim-repo`'s commit `deployable?` and triggering continuous delivery/merge scheduling it was never entitled to.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
