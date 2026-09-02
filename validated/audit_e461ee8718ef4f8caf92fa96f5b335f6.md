### Title
Cross-organization webhook forgery — signature verified against `repository.owner.login` but the acted-upon repository/commit is selected from unvalidated `repository.full_name`/`sha` fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the HMAC against based on the attacker-controlled JSON field `repository.owner.login` (or `organization.login`), not based on the repository the payload actually targets. Every event handler then acts on a completely separate field — `repository.full_name` (or, for `status`, a bare `sha` with no repository scoping at all) — to decide which `Stack`/`Commit`/`Team` gets mutated. Nothing binds "the org whose secret signed this request" to "the repository/commit that gets written."

### Finding Description
In a multi-org Shipit deployment (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`), each GitHub organization has its own `webhook_secret`.

`WebhooksController#verify_signature` picks the app/secret solely from the payload body itself: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` just HMACs the raw body with whatever secret was selected for that `repository_owner`: [3](#0-2) 

Handlers, however, resolve the target `Stack`/`Repository` using a *different* field of the same body — `repository.full_name`: [4](#0-3) [5](#0-4) 

For `status` events, there is no repository scoping check at all — commits are matched purely by `sha` across the whole install: [6](#0-5) 

Because the HMAC covers the raw body, this is not forgeable by a third party with no secret. But it *is* forgeable by anyone who legitimately possesses a valid `webhook_secret` for *any one* configured organization on the instance (e.g., an org admin who set up their own GitHub App integration for "OrgA", which is precisely the multi-tenant scenario the engine documents and supports). That admin — unprivileged with respect to every *other* org's repositories — can hand-craft (not simply relay) a JSON body where `repository.owner.login` = `"OrgA"` (so `verify_signature` selects OrgA's secret, which the attacker holds) while `repository.full_name` = `"OrgB/victim-repo"` or the `sha`/`organization.login` fields reference an entirely different org/repo/team. Signing that crafted body with OrgA's secret produces a signature Shipit accepts, and the handler then mutates state that belongs to OrgB, whose secret the attacker never possessed.

This is the same class of bug as the reported issue: a piece of state (`Boost.boostMagnitude`, there) is trusted/reused without re-validating it against the thing that actually changed, here the "authenticated organization" is never re-checked against the "written repository/commit/team," even though both are attacker-supplied fields inside the same request.

### Impact Explanation
Depending on event type, this breaks the `Shipit.github_teams` authorization boundary and stack/commit integrity for repositories the attacker has no access to:
- `membership` events let the holder of any one org's webhook secret add arbitrary GitHub logins to *any* team object (`Team.find_or_create_by!`/`add_member`) keyed only by attacker-supplied `team.id`/`organization.login`, potentially granting `Shipit.github_teams` authorization (login access to the whole Shipit instance) to arbitrary accounts. [7](#0-6)  This matches the High-severity bar: "escalation into `Shipit.github_teams` authorization."
- `status` events let the attacker inject fabricated CI status (e.g. forcing `state: success`) onto arbitrary commit SHAs belonging to any stack on the instance, since matching is done by bare `sha` with no repo/org scoping. Since Shipit's merge queue and deploy gating rely on `StatusChecker`/`all_status_checks_passed?` over these persisted statuses, this can push an unrelated stack's PR into an incorrectly "green" state and cause an unauthorized merge/deploy decision. [8](#0-7) 
- `push`/`check_suite` events let the attacker trigger `GithubSyncJob`/`RefreshCheckRunsJob` against stacks of unrelated repositories, at minimum causing the app to fetch/act on state for repos outside the attacker's authority using the app's own `GITHUB_TOKEN` credentials for that unrelated org.

### Likelihood Explanation
Requires an attacker to already hold a valid `webhook_secret` for at least one org configured in the multi-org `github:` block of `secrets.yml` — realistic in a shared/multi-tenant Shipit instance where multiple organizations (with different trust levels) each register their own GitHub App and are handed back their own `webhook_secret`. No Shipit session, `ApiClient` token, or GitHub credentials for the *victim* org are needed — only the ability to author raw HTTP requests to `/webhooks`, which requires no Shipit authentication at all (`WebhooksController` skips `Authentication`).

### Recommendation
After signature verification selects an organization via `repository_owner`, re-derive and cross-check that every repository/organization/team referenced elsewhere in the same payload actually belongs to that same organization before acting on it (e.g., assert `repository.full_name.split('/').first.casecmp?(repository_owner)`, and for `status`, scope the `Commit` lookup by the verified organization's repositories, not by bare `sha`). Reject the webhook if these do not match.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications").
2. As an administrator of OrgA's own GitHub App (an unprivileged actor with respect to OrgB), obtain OrgA's `webhook_secret` — this is data legitimately available to whoever registers OrgA's App, not to Shipit operators alone.
3. Craft a JSON body for a `status` event: `{"sha": "<victim-commit-sha-in-OrgB-stack>", "state": "success", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/irrelevant"}}`.
4. Sign the raw body with OrgA's `webhook_secret` using HMAC-SHA1 and send it to `POST /webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=<hmac>`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and verifies successfully since the attacker holds OrgA's secret; `StatusHandler#process` then matches `Commit.where(sha: ...)` regardless of organization and creates a fabricated "success" status on the victim commit belonging to `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
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
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
