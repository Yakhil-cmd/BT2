### Title
Cross-tenant webhook forgery: `verify_signature` authenticates by `repository.owner.login`, but handlers act on the independently-attacker-controlled `repository.full_name` / `organization.login` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`) read from the *same unauthenticated JSON body* it is about to verify. Once the HMAC check passes, the actual event handlers (`PushHandler`, `MembershipHandler`, `StatusHandler`, etc.) independently re-read other fields from that same body — `repository.full_name`, `organization.login` — to decide which `Stack`/`Team`/`Commit` to mutate. Because the field used to pick the verification secret and the fields used to pick the mutation target are not the same and are not cross-checked, an org that is a legitimate, separately-configured tenant of a multi-organization Shipit deployment can forge a signed webhook that is verified against its own secret while acting on a completely different organization's repository or team.

### Finding Description
In a multi-organization Shipit configuration, `Shipit.github(organization:)` maintains one `GitHubApp` (and one `webhook_secret`) per configured GitHub organization: [1](#0-0) 

`WebhooksController#verify_signature` picks which of these per-organization secrets to verify against using a value taken straight out of the untrusted request body, *before* the signature has been validated: [2](#0-1) [3](#0-2) 

Once `head(422)` is not triggered (i.e. the signature matches the secret for whatever organization `repository.owner.login` claims to be), `create` hands the entire raw JSON body to the registered handlers unmodified: [4](#0-3) 

The handlers, however, do not re-use `repository.owner.login` at all. The base `Handler` class resolves the target repository from a *different* JSON path, `repository.full_name`: [5](#0-4) 

`PushHandler` uses that repository lookup to trigger a GitHub sync on any matching stack: [6](#0-5) 

`MembershipHandler` similarly trusts `organization.login` (again independent of the field used to select the verifying secret) to create/attach the team whose members it mutates: [7](#0-6) 

Because the attacker fully controls the raw JSON body they sign, they can set `repository.owner.login` (or `organization.login`) to the name of an organization whose webhook secret they legitimately know (their own onboarded org on the shared Shipit instance) to pass `verify_signature`, while simultaneously setting `repository.full_name` (or a different `organization.login` value deeper in the payload, since GitHub webhook JSON has multiple, independently-settable "organization identity" fields) to point at a victim organization/repository also configured on the same Shipit instance. This is exactly the bug class in the referenced report: a value used for one authorization decision (`isLong`/verification side) diverges from the value the same code subsequently acts on (`!isLong`/target side), because the two reads of "which org is this" are not bound to the same field or cross-validated.

### Impact Explanation
This breaks the binding: `organization that authenticated the request == organization whose repository/stack/team is written`. A tenant organization legitimately configured on a shared Shipit instance (i.e., one that knows its own `webhook_secret`) can forge webhooks that:
- trigger `GithubSyncJob`/`sync_github` on another tenant's `Stack` (`PushHandler`), potentially manipulating deploy-eligible commit history for a repository the attacker does not own,
- create arbitrary `Team`/`Membership` records tied to an arbitrary `organization.login` string (`MembershipHandler`), which can affect `Shipit.github_teams` authorization checks used by `Authentication#force_github_authentication` for a different org's Shipit instance,
- inject fabricated commit statuses for arbitrary commits (`StatusHandler`), influencing CI-gated deploy/merge decisions for another tenant.

This matches the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact tiers defined for this engine, without requiring the attacker to hold any credential, session, or repository access for the victim organization — only knowledge of their own, separately configured tenant's webhook secret.

### Likelihood Explanation
Exploitability is limited to deployments that use Shipit's multi-organization GitHub App configuration (`github_default_organization` non-nil), where at least two independently-controlled organizations are onboarded to the same Shipit instance. In that specific but explicitly-documented configuration, any tenant admin who knows their own org's `webhook_secret` (a value they set up themselves) can exploit this with a single crafted HTTP request — no additional access is required. In the single-organization configuration (`github_default_organization` is `nil`), `repository_owner` is not used to select among multiple secrets, so the specific cross-tenant escalation does not apply, though `Shipit.github(organization: repository_owner)` is still called with a value it never authenticates against downstream repository selection.

### Recommendation
After verifying the webhook signature, re-derive the acting organization from the same trusted binding used for verification and reject (or ignore) events whose `repository.full_name` / `organization.login` do not belong to the organization the secret was selected for. Concretely, in `WebhooksController`, compare `repository_owner` against the owner portion of `repository.full_name` (and against `organization.login` for organization-level events) and `head(422)` on mismatch, so a single JSON payload cannot claim one identity for signature selection and another for the mutating handlers.

### Proof of Concept
Conceptual sequence (requires a multi-organization Shipit configuration with tenants `attacker-org` and `victim-org` both onboarded):
1. Attacker knows `webhook_secret` for `attacker-org` (its own GitHub App installation secret).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_of_attacker-org, body)` and sets `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully because the attacker knows that org's secret. [8](#0-7) 
5. `PushHandler#process` resolves the target stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github` on the victim's stack. [9](#0-8) [10](#0-9)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
