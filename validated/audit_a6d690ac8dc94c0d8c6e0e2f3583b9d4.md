### Title
Webhook authenticity is bound to `repository.owner.login`, but every event handler acts on the unverified `repository.full_name` — organization that authenticated ≠ repository that is written (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) is used to validate the inbound HMAC signature by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted JSON body, *before* any signature has been checked. Every webhook handler, however, resolves the `Stack`/`Repository` it mutates using a *different* field of the same payload: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb`). In a multi-organization Shipit deployment (the officially documented `github: { orgA: {...}, orgB: {...} }` configuration), these two fields are never cross-checked against each other, so a signature that is valid for tenant B's webhook secret can be replayed with a payload whose `repository.full_name` points at tenant A's tracked repository.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (`app_id`, `installation_id`, `webhook_secret`) from `secrets.github`, as documented for multi-org setups: [3](#0-2) [4](#0-3) 

Once `verify_signature` passes, `WebhooksController#create` dispatches to handlers with the raw, attacker-supplied `params` — it never re-checks that `repository.owner.login` matches `repository.full_name`: [5](#0-4) 

Every handler's base class resolves the target `Stack` purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

This same pattern (`params.repository.full_name`) is repeated in `PushHandler`, `StatusHandler` (via `Commit.where(sha:)`, cross-tenant since it doesn't even scope by repo), `MembershipHandler` (`params.organization.login`, again decoupled from the field used for signature verification), and the pull-request handlers: [7](#0-6) [8](#0-7) [9](#0-8) 

**Binding broken:** `organization authenticated` (the org whose `webhook_secret` validated `X-Hub-Signature`, derived from `repository.owner.login`) `≠` `repository that is written` (the `Stack`/`Repository` resolved from `repository.full_name`, or the `Team`/`organization` resolved from `organization.login` in `MembershipHandler`). Nothing in the request pipeline enforces that these two independently-attacker-controlled fields refer to the same tenant.

### Impact Explanation
In a single-GitHub-App deployment (the common case) this has no effect, because `Shipit.github(organization: nil)` always resolves to the one configured app/secret regardless of `repository_owner`, so the check is a no-op tautology. The vulnerability only manifests in the explicitly documented multi-org configuration, where each organization is issued its own GitHub App and its own `webhook_secret`.

In that configuration, an entity that legitimately administers **its own** installed GitHub App (org B) — and therefore knows/controls its own `webhook_secret_B`, which any org owner/admin can view or rotate in GitHub App settings — can:
- Sign a forged payload with `webhook_secret_B` and set `repository.owner.login`/`organization.login` = `"orgB"` so `verify_signature` picks org B's app and the signature checks out.
- Set `repository.full_name` (in `PushHandler`/PR handlers) or leave `sha` unscoped (in `StatusHandler`, which queries `Commit.where(sha:)` globally with no repository filter) to target a repository/stack that belongs to a *different*, unrelated organization (org A) tracked on the same Shipit instance.
- Deliver `status`/`check_suite` events that flip CI state to green for org A's commits, which feed `Commit#create_status_from_github!` and can enable `Stack#continuous_deployment?`-gated auto-deploys via `ContinuousDeliveryJob#perform` — i.e., an **unauthorized deploy** of another tenant's stack.
- Deliver `membership` events with `organization.login = "orgA"` to fabricate/alter `Team` membership for org A's teams, escalating into `Shipit.github_teams` authorization used to gate `RepositoriesController`/stack access.

This crosses the "unauthorized deploy" and "escalation into `Shipit.github_teams` authorization" thresholds defined as valid High/Critical impact for this scan, without requiring a Shipit session, API token, or org A's real webhook secret — only the attacker's own (legitimately obtained) org-B secret.

### Likelihood Explanation
Requires: (1) the host application to run Shipit in the documented multi-organization mode, and (2) the attacker to control/administer at least one of the configured GitHub App installations (a normal, low-privilege condition for any tenant onboarded to a shared Shipit instance) while targeting another tenant's repository that is also tracked by the same instance. This is a realistic configuration for shared/internal Shipit deployments serving multiple business units or teams, each with their own GitHub App, which is exactly the scenario `docs/setup.md`'s "Using Multiple Github Applications" section describes as supported.

### Recommendation
After signature verification succeeds, enforce that the organization used to select the verifying `webhook_secret` (`repository_owner`) matches the owner segment of `repository.full_name` (and, for `membership` events, `organization.login`) before dispatching to any handler. Reject the request (422) on mismatch. Additionally, scope `StatusHandler`'s `Commit.where(sha:)` lookup by the verified repository/stack rather than a bare SHA, to avoid cross-repository status collisions even within a single-org deployment.

### Proof of Concept
Assume a multi-org Shipit instance configured per `docs/setup.md` with two tenants:
```yaml
github:
  orgB:
    webhook_secret: "secret-B"   # known to attacker, who administers OrgB's GitHub App
  orgA:
    webhook_secret: "secret-A"   # NOT known to attacker; orgA/repo1 is tracked by Shipit
```
1. Attacker crafts a `push` (or `status`/`check_suite`/`membership`) payload:
```json
{
  "repository": { "owner": { "login": "orgB" }, "full_name": "orgA/repo1" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already known to exist upstream>"
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(secret-B, raw_body)>` using their own, legitimately-known `secret-B`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orgB")`, which verifies successfully against `secret-B` — the request passes even though the payload's `full_name` targets `orgA/repo1`.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgA/repo1")` and calls `stack.sync_github(...)`, mutating org A's stack state despite the attacker never possessing `secret-A`. [10](#0-9) [11](#0-10)

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
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
    end
  end
end
```
