## Title
`WebhooksController` binds signature verification to `repository.owner.login` but processes handlers against the unrelated, self-reported `repository.full_name` — organization authenticated ≠ repository written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a value read straight out of the still-unauthenticated JSON body (`params.dig('repository','owner','login')`). The same untrusted body is then handed unmodified to the event handlers, which resolve the actual `Stack`/`Team` to mutate using a *different* field of the same body: `payload.dig('repository','full_name')` (for push/status/PR handlers) or `params.organization.login` / `params.team` (for the membership handler). Nothing cross-checks that the org used to pick the verification secret is the same org embedded in the fields that drive the write path.

### Finding Description
- Verification: `app/controllers/shipit/webhooks_controller.rb#verify_signature` (lines 24-30) resolves `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`. [1](#0-0) 
- `repository_owner` is defined purely from the JSON payload with no relation enforced to any other field of the same payload: [2](#0-1) 
- `verify_webhook_signature` in `lib/shipit/github_app.rb` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured — a supported, documented configuration (`docs/setup.md` describes `webhook_secret` as optional): [3](#0-2) 
- After verification, the **entire raw JSON body** (not just the verified org) is dispatched to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
- Handlers such as `PushHandler` resolve the target `Stack` using `payload.dig('repository', 'full_name')` — a completely independent JSON field from the one used for signature-org selection: [5](#0-4) 
- `MembershipHandler` is worse: it trusts `params.organization.login`, `params.team`, and `params.member.login` outright to create/attach `Team`/`Membership` records that directly gate application-wide authorization via `User#authorized?`: [6](#0-5) [7](#0-6) 

In a multi-organization Shipit deployment (`config: github: <org>: ...` per `docs/setup.md#L182-209`), if *any* configured organization is left without a `webhook_secret` (explicitly supported, e.g. `test/dummy/config/secrets.test.json` sets `"webhook_secret": null`), an unauthenticated attacker can:
1. Send a POST to `/github/webhooks` (or the mounted webhook path) with `X-Github-Event: membership`.
2. Set `repository.owner.login` (or `organization.login` used as fallback) to the org that has no webhook secret configured, so `verify_webhook_signature` trivially passes with `true` regardless of the (even absent) signature header.
3. Independently set the payload's `organization.login`, `team`, and `member.login` fields to values naming a **different**, real team belonging to a *secured* organization (e.g. one referenced by `Shipit.github_teams`), causing `MembershipHandler#process` to add the attacker-controlled GitHub login as a member of that team.
4. That newly created `Membership` satisfies `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`), granting the attacker's Shipit account access to the entire Shipit UI (deploy/rollback pages) that is otherwise gated behind team membership.

This is a structural analog to the reported "rounding down" issue: the value relied upon by the trust boundary (the org whose secret gates the request) is decoupled from the value that determines the actual state mutation (the org/team/repo actually written), and the code never re-derives or asserts equality between the two — exactly the "authenticated field vs. acted-upon field" mismatch called out in the rules ("an organization that authenticated versus the repository that is written").

### Impact Explanation
Successful exploitation escalates an unprivileged, unauthenticated network attacker into `Shipit.github_teams` authorization by fabricating `Membership` records via the `membership` webhook — this maps directly to the in-scope High-severity bucket ("escalation into `Shipit.github_teams` authorization"). It also allows spoofing `push`/`status`/`check_suite` events against arbitrary stacks that belong to organizations other than the one whose (missing) secret gated the request, since `PushHandler`/`Handler#repository_name` reads `repository.full_name` independent of `repository_owner`.

### Likelihood Explanation
Requires: (a) a multi-organization Shipit deployment, and (b) at least one configured organization lacking a `webhook_secret`. Both are supported, documented configurations rather than misconfiguration bugs (`docs/setup.md` marks `webhook_secret` optional; the codebase explicitly special-cases `webhook_secret` being blank as "always verified"). No credentials, tokens, or prior access are required — the webhook endpoint is unauthenticated by design (it authenticates via HMAC instead). This is plausible in real deployments but conditional on that specific optional configuration; I could not verify from the indexed code/docs how commonly operators omit `webhook_secret` in practice, nor confirm the exact mount path/route for `WebhooksController` from `config/routes.rb`, since routing details were not surfaced in my search.

### Recommendation
- Derive the organization used for handler processing (`repository_name`/`organization.login`/`team.organization`) from the same authenticated context as `repository_owner`, and reject the request if fields disagree (e.g., verify that `repository.full_name`'s owner segment equals `repository_owner`, and that `MembershipHandler`'s `organization.login` equals `repository_owner`).
- Do not allow `verify_webhook_signature` to unconditionally return `true` when `webhook_secret` is blank for an organization that is not the sole tenant of the instance; require a secret whenever more than one organization is configured, or bind the signature check per-organization strictly instead of falling back permissively.
- Consider requiring `MembershipHandler` to independently confirm team membership via the GitHub API instead of trusting the raw webhook body for something as sensitive as authorization-team membership.

### Proof of Concept
Given a multi-org Shipit config where org `no-secret-org` has `webhook_secret: nil` and `Shipit.github_teams` includes `secured-org/admins`:

```
POST /github/webhooks
X-Github-Event: membership
(no valid X-Hub-Signature required)

{
  "action": "added",
  "team": { "id": 999, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "secured-org" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "no-secret-org/whatever" }
}
```

`verify_signature` calls `Shipit.github(organization: "no-secret-org")` → `webhook_secret` is blank → `verify_webhook_signature` returns `true` unconditionally, bypassing the check entirely. `MembershipHandler#process` then executes using `organization.login = "secured-org"` and `team.id = 999`, creating/attaching `attacker-github-login` to team `secured-org/admins`, satisfying `User#authorized?` for that account on next login. [8](#0-7) [3](#0-2) [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-44)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
