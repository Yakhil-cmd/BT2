I have enough evidence to confirm this finding.

### Title
Webhook signature is verified against a GitHub App selected by an unverified payload field, while handlers act on a different, unbound repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App configuration (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a value read directly out of the untrusted, attacker-suppliable JSON body — before the signature has been checked. Every downstream webhook `Handler` then acts on a completely different payload field, `repository.full_name`, to look up the `Stack`/`Repository` to operate on. In a multi-organization deployment (`secrets.github` keyed by org, see `Shipit.github_app_config`), these two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and "the repository the handlers actually write to" are not the same binding.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 

and `repository_owner` itself is derived from the raw body, with no verification yet applied: [3](#0-2) 

`Shipit.github(organization:)` maps that organization name to a distinct `webhook_secret` from `secrets.github` (per-org config), via `github_app_config`: [4](#0-3) 

Once `verified` is true (using whichever org's secret matched `repository_owner`), `create` dispatches to handlers using the *entire* raw payload, unconstrained to that same organization: [5](#0-4) 

Every default handler (`PushHandler`, `PullRequest::*Handler`, `StatusHandler`, etc.) resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')`, a field completely independent of `repository.owner.login`: [6](#0-5) [7](#0-6) 

This is the exact binding violation the rule set calls out: "an organization that authenticated versus the repository that is written." The equality that should hold is:

`organization used to select webhook_secret for HMAC verification == organization that owns repository.full_name acted on by the handler`

In this code, nothing enforces that equality; the two lookups are structurally decoupled.

### Impact Explanation
In any Shipit deployment configured with the multi-org `secrets.github` schema (documented and supported, see `test/dummy/config/secrets_double_github_app.yml` and `github_app_config`), an attacker who is a legitimate, unprivileged GitHub user/admin of *any one* organization onboarded to that Shipit instance (Org A) knows or can obtain Org A's `webhook_secret` (it is configured by that org's own GitHub App owner and would be known to anyone who administers Org A's GitHub App). Using that secret, they can sign an arbitrary payload whose `repository.owner.login` = `OrgA` (satisfying the signature-selection field), but whose `repository.full_name` = a repository belonging to Org B (any other org/stack hosted on the same Shipit instance). Because handlers only look at `full_name`/`Repository.from_github_repo_name`, the forged event is accepted and processed against Org B's stack — e.g. triggering `GithubSyncJob`/`stack.sync_github`, closing/archiving review stacks, injecting fake commit statuses, or creating memberships — all without ever holding Org B's `webhook_secret` or any credential for Org B. This is a cross-repository/cross-organization write achieved purely by crafting the payload's owner field, which matches the Critical "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Exploitability requires only: (1) the target Shipit instance uses the multi-org `github:` secrets schema (a documented, supported configuration, not a fringe case — see `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`), and (2) the attacker administers or otherwise possesses the `webhook_secret` of *any one* onboarded organization (which is by design knowable to that org's own GitHub App owner, an unprivileged party with respect to other orgs on the shared Shipit instance). No Shipit session, API token, or GitHub write access to the victim repository is needed — only a raw HTTP POST to `/github/webhooks` with a forged `X-Hub-Signature`.

### Recommendation
In `WebhooksController#verify_signature`, after selecting `github_app` via `repository_owner` and verifying the HMAC, additionally assert that `payload.dig('repository', 'full_name')` (or `organization.login` for org-level events) belongs to the same organization used to resolve `github_app`/the `webhook_secret` — e.g., compare the owner segment of `full_name` against `repository_owner`, and reject (422) on mismatch. Alternatively, look up the `Repository`/`Stack` first and use *its own* configured organization/secret to verify the signature, rather than trusting an unverified payload field to pick the secret.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `OrgA` (webhook_secret `secretA`) and `OrgB` (webhook_secret `secretB`), each with a stack backed by a repository, e.g. `OrgA/repoA` and `OrgB/repoB`.
2. As an ordinary member/owner of `OrgA` only (no access to `OrgB` or Shipit itself), craft a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgB/repoB",
    "owner": { "login": "OrgA" }
  }
}
```
3. Sign the raw JSON body with `secretA` (`sha1=<HMAC-SHA1(secretA, body)>`) and send it as `X-Hub-Signature`, with header `X-Github-Event: push`, to the Shipit webhooks endpoint.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')`, verifies successfully against `secretA`.
5. `PushHandler` resolves `Repository.from_github_repo_name('OrgB/repoB')` and triggers `stack.sync_github(expected_head_sha: params.after)` on Org B's stack, an organization/repository the attacker never had signing credentials for.

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
