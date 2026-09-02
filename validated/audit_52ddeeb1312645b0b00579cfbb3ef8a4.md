### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but every event handler acts on the unrelated `repository.full_name` / `organization.login` fields from the same forged payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub organizations behind one instance, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to check the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body, before the signature has been validated: [2](#0-1) . Once the signature check passes, `create` dispatches the very same raw `params` hash to the registered handlers [3](#0-2) , but the handlers resolve the target repository from a *different* field, `repository.full_name`, via `Handler#repository_name`/`#stacks` [4](#0-3) , or from `organization.login` for membership events [5](#0-4) . Nothing cross-checks that the owner used to pick the signing secret matches the owner/organization the handler actually mutates.

### Finding Description
The binding that should hold is: `organization used to verify signature == organization whose repository/team is written`. It does not.

- `verify_signature` picks the `GitHub App` config purely from `params.dig('repository','owner','login')` (fallback `params.dig('organization','login')`), all attacker-controlled JSON, and only afterwards compares the raw body's HMAC against that org's `webhook_secret` [6](#0-5) , [7](#0-6) .
- `Shipit.github(organization:)` looks up per-organization secrets from `secrets.github[organization]`, confirming this multi-tenant secret model is a supported, documented configuration [8](#0-7) .
- Push events resolve the target `Stack`/`Repository` from `repository.full_name`, an independent JSON field never compared to `repository.owner.login` [4](#0-3) , [9](#0-8) .
- Status events resolve the target purely from `sha` and apply it to any matching `Commit` in the database, regardless of organization [10](#0-9) .
- Membership events create/join `Team`s using `params.organization.login`/`params.team`, and grant/revoke membership on that basis [11](#0-10) , and `Team` records back `Shipit.github_teams`, the OAuth-authorization gate used across the UI/API controllers [12](#0-11) .

Concretely: on a Shipit deployment configured for multiple GitHub organizations (a documented setup [1](#0-0) ), anyone who legitimately knows one organization's `webhook_secret` (e.g. the admin of their own onboarded org/GitHub App on the same shared instance — no Shipit session, `ApiClient` token, or repo write access required) can sign an arbitrary JSON body with that secret while setting `repository.owner.login` to their own org (so signature verification passes) but `repository.full_name` (or `organization.login`) to a *different*, victim organization/repository tracked by the same instance. The signature check is satisfied against the attacker's own known secret, yet the handler acts on the victim's data.

### Impact Explanation
This breaks the "organization authenticated vs. repository/organization written" binding called out as the bug-class target. Reachable impacts:
- **StatusHandler**: forge a `success` commit status on a victim repository's commit, which can satisfy `ci.require` gating and enable an **unauthorized deploy** of that commit [10](#0-9) .
- **PushHandler**: trigger `stack.sync_github` against a victim stack the attacker does not own, forcing synchronization/state changes on it [13](#0-12) .
- **MembershipHandler**: create/associate `Team` records and add arbitrary GitHub users to teams that back `Shipit.github_teams` authorization, an **escalation into `Shipit.github_teams` authorization** [11](#0-10) , [12](#0-11) .

These map to the listed High-severity impact categories (unauthenticated cross-organization writes / escalation into `Shipit.github_teams` authorization), and the status-forgery path can chain into an unauthorized deploy (Critical).

### Likelihood Explanation
Exploitability requires only that the target Shipit instance is configured for **multiple GitHub organizations** with separate `webhook_secret`s (an explicitly documented, supported configuration) and that the attacker controls (owns/administers) at least one of those onboarded organizations/GitHub Apps — a low bar compared to the excluded scenarios (no Shipit session, `ApiClient` token, repository write access, or GitHub App private key is needed; the attacker only needs a `webhook_secret` for an org they legitimately administer, which is not itself a privileged secret for the *victim's* org). On single-organization deployments this specific analog does not apply, since there is only one `webhook_secret` to select from.

### Recommendation
After verifying the HMAC signature, re-derive the acting organization/repository strictly from the same field used for verification (`repository.owner.login`), and reject or ignore any event whose `repository.full_name` owner or `organization.login` does not match the organization whose secret validated the signature. Handlers should receive the already-authenticated organization context rather than re-parsing owner/org identifiers from the untrusted payload body.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org schema).
2. Attacker (who legitimately administers `attacker-org`'s GitHub App and therefore knows `attacker-org`'s `webhook_secret`) crafts a `status` webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     "sha": "<victim commit sha>",
     "state": "success"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature verifies successfully [14](#0-13) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's commit — and records a fabricated `success` status on it, entirely independent of the organization used for verification [10](#0-9) .

### Citations

**File:** docs/setup.md (L18-38)
```markdown
2. Run this command:  `rails _8.0_ new shipit --skip-action-cable --skip-turbolinks --skip-action-mailer --skip-active-storage --skip-webpack-install --skip-action-mailbox --skip-action-text -m https://raw.githubusercontent.com/Shopify/shipit-engine/main/template.rb`

## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
  - Repository permissions:
    - Checks: Read & write
    - Commit statuses: Read-only
    - Contents: Read & write (to allow merging)
    - Deployments: Read & write
    - Issues: Read & write (to allow closing related issues on merge)
    - Metadata: Read-only
    - Pull requests: Read & write
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
