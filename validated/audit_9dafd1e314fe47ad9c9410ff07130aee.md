### Title
Webhook signature is verified against the organization named in the payload's `repository.owner`/`organization` field, but the events are then processed against a `repository.full_name` (or bare commit `sha`) that is never checked against that authenticated organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, a value taken straight from the attacker-controlled JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches the very same raw JSON body to handlers (`PushHandler`, `PullRequest::*Handler`, `MembershipHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) that determine *which stack/commit to mutate* using a different, unrelated field of that same body: `repository.full_name` (via `Shipit::Webhooks::Handlers::Handler#repository_name`) or, in the case of `StatusHandler`, nothing but the bare `sha` value. Neither of these fields is cross-checked against the organization whose secret authenticated the request. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
This is a direct analog of the report's root cause: a signature that authorizes one field of a request is silently reused to authorize a different field that is actually acted upon.

- Equality that is supposed to hold: `organization authenticated by webhook_secret == organization/repository whose Shipit state is mutated`.
- What the code actually checks: `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_body)`, where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [5](#0-4)  — this only proves that the *sender who signed the raw body* knows the `webhook_secret` configured for whichever organization name appears in that field of the payload.
- What actually gets written: every default handler resolves the target stack independently, from `repository.full_name` [3](#0-2) , or, worse, `StatusHandler` ignores the repository entirely and updates **every** `Commit` row across the whole install that happens to share the attacker-chosen `sha`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .

Since Shipit's multi-tenant configuration (`Shipit.github(organization: X)`) allows different organizations to each have their own registered GitHub App and `webhook_secret` [6](#0-5) , an operator/admin of *their own* legitimately-configured organization ("attacker-org") knows their own `webhook_secret` and can therefore produce a validly-signed POST to `/webhooks` whose JSON body's `repository.owner.login` is `"attacker-org"` (so `verify_signature` picks and passes against attacker-org's secret) while the same body's `repository.full_name` (or a bare `sha`) names or matches a completely different, victim-owned repository/commit tracked by Shipit. The handler layer never checks that `repository.owner.login`/`organization.login` (the authenticated field) matches `repository.full_name`'s owner, or that the commit's stack belongs to the authenticated organization at all.

### Impact Explanation
The most severe reachable outcome is via `StatusHandler`: because it looks up commits purely by `sha` with no owner/repo scoping at all, an attacker who knows any victim commit SHA that also exists in their own signed payload can forge a passing CI status (`state: "success"`, matching `context`) on that commit. `Commit#deployable?` and `required_statuses` gate deploys directly on stored statuses [7](#0-6) , and shipit.yml's `ci.require` is enforced from this cached status data [8](#0-7) . This lets an attacker who only administers their own (unrelated) organization mark a victim's commit as CI-passing, satisfying the `require_ci` deploy gate for a stack they do not own/administer and enabling an unauthorized deploy of a commit that never actually passed CI — matching the Critical "unauthorized deploy" bucket. `PushHandler`/`PullRequest` handlers extend the same organization/repository-binding gap to sync/PR-provisioning writes on victim stacks resolved only by attacker-supplied `repository.full_name`.

### Likelihood Explanation
Requires only that the attacker administers (or has webhook-signing capability for) any organization/app configured in the same multi-tenant Shipit instance, no access to the victim organization, GitHub App, session, or `ApiClient` token is needed — the attacker crafts the whole JSON body themselves and signs it with their own known secret. No race condition or timing dependency is needed (unlike the original MagicSpend front-run), making this arguably easier to exploit reliably than the original report.

### Recommendation
Bind the signature verification to the same value used for stack/commit resolution: after `verify_signature`, re-derive `repository.full_name`'s owner (or `Repository#owner`) and require it to equal the organization whose `webhook_secret` validated the signature (i.e., reject if `repository_owner != Repository.from_github_repo_name(payload.dig('repository','full_name'))&.owner`). For `StatusHandler`, scope the `Commit` lookup by repository/stack, not by bare `sha` alone.

### Proof of Concept
Given a multi-tenant Shipit deployment where `attacker-org` has its own registered GitHub App/`webhook_secret` (known to the attacker) and `victim-org/victim-repo` is a separately configured stack:

1. Attacker builds a raw JSON body for a `status` event:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"}
}
```
2. Attacker computes `sha1=HMAC(attacker-org webhook_secret, raw_body)` and sends it as `X-Hub-Signature` with `X-Github-Event: status` to `/webhooks`.
3. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches attacker-org's app config, and the signature validates successfully [1](#0-0) .
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit row regardless of repository — and calls `create_status_from_github!`, forging a passing CI status on a commit the attacker does not control [4](#0-3) .
5. If `victim-org/victim-repo`'s `shipit.yml` lists `ci/required-check` under `ci.require`, the victim commit now satisfies `Commit#deployable?`/`require_ci`, enabling deploys that bypass real CI results.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```
