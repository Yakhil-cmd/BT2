### Title
Webhook signature is authenticated against an organization taken from the untrusted payload, letting any onboarded org forge CI status/push events for a repository owned by a *different* org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) used to validate an inbound webhook by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body, via `repository_owner`. [1](#0-0) [2](#0-1)  The event handlers that subsequently act on the payload, however, key off a completely different field — `repository.full_name` — to decide which repository/commit the event applies to. [3](#0-2)  Because these two fields are never cross-checked, whoever holds a valid `webhook_secret` for *any* org configured on the instance (Shipit explicitly supports multiple independently-configured GitHub Apps/orgs, each with its own secret, per `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`) can sign a payload with their own org's secret while pointing `repository.full_name`/`sha` at a completely different, unrelated org's stack/commit.

### Finding Description
- `verify_signature` computes `repository_owner` from the raw JSON body and does `Shipit.github(organization: repository_owner)` to obtain the `GitHubApp` (and its `webhook_secret`) used for `verify_webhook_signature`. [4](#0-3) 
- `Shipit.github` resolves a distinct `GitHubApp`/secret per organization when the multi-org config schema is used. [5](#0-4) 
- The `status` handler ignores organization/repository scoping entirely: it looks up `Commit.where(sha: params.sha)` globally across the whole database and writes a `Status` record for every match. [6](#0-5) 
- `Status` creation is not inert: it toggles `enable_ci_on_stack`, and schedules continuous delivery for the commit. [7](#0-6) 
- `Commit#deployable?` treats a `success` status (with no blocking) as sufficient to allow deploy, regardless of provenance. [8](#0-7) 

Binding broken: **the organization whose secret authenticated the request ≠ the repository/commit that is written to.** The signature only proves "this request was signed by Org B's webhook secret"; it is then used to authorize writes against Org A's commit/stack, because the repository-identifying field consumed by the handler was never part of the signature-selection logic's trust boundary — an attacker can freely diverge the two fields within one signed body.

### Impact Explanation
An attacker who legitimately owns/administers one org onboarded to a multi-tenant Shipit instance (and therefore knows that org's own `webhook_secret`, which self-service org admins configure themselves per `docs/setup.md`'s "Using Multiple Github Applications" section) can forge a `status` event for an arbitrary commit sha belonging to a *different* org's stack, injecting a fabricated `state: success` for a required CI context. This satisfies `Commit#deployable?`'s required-status check and can trigger `schedule_continuous_delivery`, resulting in an **unauthorized deploy** of a commit that never passed real CI on a stack/repository the attacker has no legitimate access to. This meets the Critical bar ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only: (1) the attacker administers/onboards their own org on a multi-org Shipit deployment (a supported, documented configuration) and thus knows their own org's webhook secret, and (2) knowledge of a target commit's sha (visible in Shipit's own UI/API or GitHub). No GitHub App private key, no `ApiClient` token, and no privileged Shipit account are required — only the attacker's own, legitimately-issued webhook secret for their own org.

### Recommendation
Bind webhook signature verification to the same repository/organization the handler will act on: derive the trusted organization from the `Stack`/`Repository` record matched by `repository.full_name` (or require the signing org to match `repository.owner.login` used by the handler), rather than trusting an unauthenticated field to pick the verification secret. Additionally, `StatusHandler` (and any other global `Commit`/`Stack` lookups keyed only by `sha`) should scope lookups to the repository asserted in the same payload that was validated, and reject cross-organization mismatches outright.

### Proof of Concept
1. Operator runs Shipit with two orgs configured (`OrgA`, `OrgB`), each with its own `webhook_secret`, per the documented multi-org schema. [9](#0-8) 
2. Attacker administers `OrgB` and knows `OrgB`'s `webhook_secret`.
3. Attacker crafts a POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha-of-a-commit-in-OrgA's-stack>",
  "state": "success",
  "context": "ci/required-context",
  "repository": { "full_name": "OrgA/private-repo", "owner": { "login": "OrgB" } }
}
```
signed with `sha1=HMAC_SHA1(OrgB_webhook_secret, raw_body)` in `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `"OrgB"`, fetches `Shipit.github(organization: "OrgB")`, and the signature validates successfully since it was signed with `OrgB`'s real secret. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (no org scoping) and creates a forged `success` `Status` for `OrgA`'s commit. [10](#0-9) 
6. If `OrgA`'s stack has continuous deployment enabled, the forged status can trigger an unauthorized deploy of that commit.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** app/models/shipit/status.rb (L16-22)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```
