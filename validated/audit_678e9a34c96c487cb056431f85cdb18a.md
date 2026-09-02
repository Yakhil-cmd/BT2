### Title
Webhook signature is verified against an org derived from an unauthenticated payload field, letting any onboarded organization forge status/push events for repositories it does not own - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using a field taken from the same unauthenticated JSON body it is about to validate. The repository/commit that downstream handlers act on (`StatusHandler`, `PushHandler`) is never re-checked against that same organization. In a multi-org Shipit deployment, any organization onboarded to Shipit (and therefore possessing a valid `webhook_secret`) can sign a payload that is verified for its own org while acting on a commit/repository belonging to a different, victim stack.

### Finding Description
`verify_signature` computes the app to check the signature with from data inside the untrusted request body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`), and `Shipit.github(organization: repository_owner)` is used purely to pick the `webhook_secret` to HMAC-verify the raw body. Shipit explicitly supports multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret`: [3](#0-2) 

Once the signature is accepted, the event is dispatched to handlers that resolve their target purely from other fields of the *same* payload, with no cross-check that those fields belong to the organization whose secret validated the request: [4](#0-3) [5](#0-4) [6](#0-5) 

`StatusHandler` is the sharpest instance: it matches purely by `Commit.where(sha: params.sha)`, with **no repository/owner check at all**. `PushHandler` resolves stacks via `Repository.from_github_repo_name(...)` reading `repository.full_name`, a field distinct from `repository.owner.login` used for signature selection — nothing enforces that `full_name`'s owner equals `repository_owner`.

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization owning the repository/commit the handler mutates`

This binding is never enforced; the equality can be broken by simply setting `repository.owner.login` (or `organization.login`) to the attacker's own onboarded org (so the correct, known `webhook_secret` is selected and verification passes) while `sha` (for `status`) or `repository.full_name` (for `push`) refers to a victim stack/repository configured under a different organization.

### Impact Explanation
An attacker who administers any single organization onboarded into a multi-org Shipit instance (and thus legitimately knows that org's `webhook_secret`, since they installed/configured the GitHub App themselves) can forge:
- `status` events for **any commit sha known to the attacker** (e.g., discovered via the public GitHub commit history of a victim repo) to inject arbitrary CI `success`/`pending`/`failure` statuses onto commits belonging to stacks in a completely different, unrelated organization — this can satisfy CI requirements gating deploys/merges.
- `push` events referencing a victim `repository.full_name`, triggering `stack.sync_github(expected_head_sha: ...)` for that stack even though the signature was validated only against the attacker's own org.

This maps to the impact category "escalation ... unauthorized deploy, rollback or merge" since forged CI status can unblock `Stack` deploy gating (`ci.require`) or merge-queue logic that depends on commit statuses, and forged push events can desynchronize a victim stack's deploy state.

### Likelihood Explanation
Requires the attacker to control (own or administer) at least one organization that has legitimately been onboarded to the same Shipit instance with its own GitHub App/`webhook_secret` — a realistic scenario for any multi-tenant/multi-org Shipit deployment (explicitly documented and supported, see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`). No privileged Shipit account, API token, or victim's webhook secret is required — only knowledge of a victim commit sha or repository full name, both of which are typically public/discoverable via GitHub.

### Recommendation
Enforce the equality that the report's mitigation pattern implies: after selecting `github_app`/`webhook_secret` by `repository_owner`, downstream handlers must validate that any repository/owner/sha referenced in the payload actually belongs to that same, verified organization before acting (e.g., look up the `Stack`/`Commit`'s `Repository#owner` and assert it matches `repository_owner`; for `StatusHandler`, scope the `Commit` lookup by the commit's repository owner, not just `sha`). Reject events where the acted-upon repository's owner does not match the organization whose secret verified the signature.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` (attacker controls the GitHub App, knows its `webhook_secret`) and `victim-org` (hosts stack `victim-org/victim-repo`), per the multi-org schema in `lib/shipit.rb#github_app_config` / `secrets_double_github_app.yml`.
2. Attacker crafts a `status` webhook JSON body:
   ```json
   {
     "sha": "<victim commit sha, e.g. from public GitHub>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-38`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of organization — and calls `commit.create_status_from_github!(params)`, injecting a forged `success` status onto a commit in `victim-org/victim-repo` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), potentially satisfying CI requirements gating that stack's deploy/merge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
