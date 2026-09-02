This confirms the vulnerability. `Shipit.github(organization:)` maintains a per-organization config map (`secrets.github` keyed by organization) where each organization has its own independent `webhook_secret`, as documented in `config/secrets.development.shopify.yml` (multiple orgs: `somegithuborg`, `someothergithuborg`, each with their own `webhook_secret`). The webhook controller selects which organization's secret to verify against using an attacker-controlled field, breaking the binding between "the organization whose secret validated the signature" and "the repository the webhook handler actually writes to."

### Title
Webhook signature validated against attacker-chosen organization while payload writes to a different, unrelated repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App config (and thus the HMAC secret) used to validate `X-Hub-Signature` based on `repository.owner.login` read directly from the untrusted, not-yet-verified request body. Meanwhile, the actual event handlers (`PushHandler`, `StatusHandler`, `Handler#stacks`) resolve the target `Stack`/`Repository` using `repository.full_name` from that same body. Because Shipit is multi-tenant (`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization, per `lib/shipit.rb`), an attacker who legitimately controls one configured organization (and therefore knows that organization's real `webhook_secret`) can craft a payload where `repository.owner.login` names their own organization (so the signature check passes with a secret they legitimately possess) while `repository.full_name` names a repository belonging to a completely different, victim organization also configured on the same Shipit instance.

### Finding Description [1](#0-0) 

`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses it to pick which `GitHubApp` (and thus which `webhook_secret`) to validate the signature against, via `Shipit.github(organization: repository_owner)`.

`Shipit.github` maintains per-organization app configs (`github_app_config`), each with its own independent `webhook_secret`: [2](#0-1) 

Handlers, however, resolve *which repository/stack to act on* using `repository.full_name`, a different sub-field of the same payload: [3](#0-2) [4](#0-3) 

For `status` events, the target is even less scoped — `StatusHandler` matches by `sha` alone across *all* stacks with a commit of that SHA, with no repository check at all: [5](#0-4) 

Because the HMAC verification "authenticates" whichever organization the attacker names in `repository.owner.login`, and that field is never cross-checked against `repository.full_name` (the field actually used to select the target repository/stack), an attacker who is a legitimate GitHub org admin for **any one** organization configured in this Shipit instance (and therefore knows that org's real `webhook_secret`) can forge a payload with a mismatched `owner.login`/`full_name` pair and pass signature verification while writing to a victim organization's stack.

Equality that should hold but doesn't: `organization used to select/verify webhook_secret == organization owning the repository the handler writes to`. The code lets an attacker make these two independently, both drawn from unauthenticated data prior to (and unrelated by) the signature check.

### Impact Explanation
This breaks cross-repository/cross-tenant isolation on a multi-tenant Shipit deployment:
- Forging a `status` event lets the attacker inject arbitrary commit statuses (`state: success`) onto a victim's tracked commit SHA (if it exists in another stack), potentially satisfying CI requirements gating `Stack#deployable?` and unblocking or triggering an unauthorized deploy via continuous delivery (`Status#after_create :enable_ci_on_stack`, `schedule_continuous_delivery`).
- Forging a `push` event with a matching `repository.full_name` triggers `GithubSyncJob`/`sync_github` against the victim's stack, an unauthorized cross-repository action.
- Forging a `membership` event can add/remove memberships on teams tied to organizations the attacker does not administer, since `MembershipHandler` derives the target `Team.organization` from `params.organization.login` — however note in that specific handler the field used for signature selection and the field used for the write are the *same* field, so membership is not exploitable this way; it's push/status/check_suite events where the fields diverge.

This satisfies the "cross-repository writes" / "unauthorized deploy" criteria for High/Critical impact.

### Likelihood Explanation
Requires the attacker to be a legitimate admin of at least one GitHub organization/repository that is configured in the same Shipit deployment as the victim (multi-tenant setup, as shown by `config/secrets.development.shopify.yml` documenting multiple orgs). This is a realistic scenario for shared/hosted Shipit instances serving many teams or customer organizations, where each org's own webhook admin should only be trusted with respect to their own repositories.

### Recommendation
Cross-validate that the organization used to select the verification secret matches the organization of the repository/stack actually targeted by the payload (e.g., re-derive `repository_owner` from `repository.full_name` split, or require they match) before verification succeeds, and ensure handlers reject events where the verified organization doesn't own the target repository (e.g., `StatusHandler` should scope by repository/stack, not by bare SHA across all stacks).

### Proof of Concept
1. Shipit is configured with two orgs, e.g. `attacker-org` and `victim-org`, each with a distinct `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. Attacker is an admin of `attacker-org` and knows its `webhook_secret`.
3. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` and POSTs directly to `/github/webhooks` (bypassing GitHub entirely, since this is a public HTTP endpoint).
5. `verify_signature` reads `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the signature validates successfully (attacker used the correct secret for that org).
6. `StatusHandler#process` (or `PushHandler` via `full_name`) creates a `Status` record on the victim's commit / triggers a sync job on `victim-org/victim-repo`, an org the attacker does not control.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
