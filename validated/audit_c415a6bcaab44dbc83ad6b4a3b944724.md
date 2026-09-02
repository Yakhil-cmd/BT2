### Title
Webhook signature is verified against the secret of the organization named in the (attacker-controlled) `repository.owner.login` field, not the organization that actually owns the repository acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to use for HMAC verification based on an unverified field of the incoming JSON body (`repository.owner.login` / `organization.login`), while the downstream handlers act on a *different* unverified field (`repository.full_name`) to decide which `Stack`/`Repository` to mutate. Nothing cross-checks that the organization whose secret validated the signature actually owns the repository that gets acted upon.

### Finding Description
`verify_signature` computes `repository_owner` straight from the untrusted payload and uses it only to pick which `GitHubApp` (and thus which `webhook_secret`) to verify the signature against: [1](#0-0) [2](#0-1) 

Because Shipit supports multiple GitHub Apps/organizations, each with its own independently-chosen `webhook_secret` in `secrets.yml`: [3](#0-2) 

...an operator who legitimately controls one configured organization (and therefore legitimately knows that organization's own `webhook_secret`, since they chose it when creating their GitHub App) can craft an arbitrary JSON body, set `repository.owner.login`/`organization.login` to *their own* organization (so `Shipit.github(organization: repository_owner)` resolves to the secret they know), sign it correctly, and set `repository.full_name` to a victim organization's repository. `PushHandler` (and other handlers) then resolve the acted-upon `Stack` purely from that second, unverified field: [4](#0-3) [5](#0-4) 

No code compares `repository_owner` (the field the signature was validated for) against `repository.full_name`'s owner segment (the field actually used to select which stack is synced). `Shipit.github_app_config` merely looks up the org name in the credentials hash; it has no relationship-enforcement to the repository being referenced elsewhere in the same payload: [6](#0-5) 

This is a structural analog of the reported bug class: the signature (the "factory") legitimately authenticates *an* organization, but the code never checks that the entity actually written/acted upon (`repository.full_name`'s Stack) is the one that organization is authorized to control.

### Impact Explanation
An attacker who administers any one of the configured GitHub organizations (a normal, low-privilege scenario in a multi-org Shipit deployment - e.g. any org onboarded for their own repos) can forge webhook deliveries that are valid per Shipit's signature check but reference another organization's/repository's stack. Via `PushHandler`, this results in `stack.sync_github(expected_head_sha: ...)` being invoked for a victim's `Stack` with an attacker-chosen `after` SHA, and via other handlers (`status`, `check_suite`, `membership`) attacker-controlled state (commit statuses, check-run refreshes, team memberships) can be pushed onto a victim's stack/commits — an unauthorized cross-repository write into another tenant's deployment pipeline.

### Likelihood Explanation
Requires the deployment to use the documented multi-organization GitHub App configuration and requires the attacker to control at least one of the configured orgs (i.e., be a legitimate but unprivileged tenant of the Shipit instance) — no `ApiClient` token, no victim's `webhook_secret`, and no privileged Shipit account are needed. This is a realistic configuration for any Shipit instance shared across multiple orgs/teams as documented in `docs/setup.md`.

### Recommendation
After verifying the HMAC signature, re-derive the organization from the same trusted, signature-selecting field and enforce that every repository referenced elsewhere in the payload (`repository.full_name`, `organization.login`) belongs to that same organization before dispatching to handlers. Alternatively, bind each configured GitHub App/secret to an explicit allow-list of organizations/repositories it is permitted to reference, and reject webhooks whose internal fields disagree.

### Proof of Concept
1. Deploy Shipit with the multi-org config from `docs/setup.md` (`github: { org-a: {...}, org-b: {...} }`), where the attacker controls `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker signs the raw body with `org-a`'s known `webhook_secret` and sets `X-Hub-Signature` accordingly.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and validates successfully.
5. `PushHandler#process` looks up stacks via `Repository.from_github_repo_name("org-b/victim-repo")`, unrelated to `org-a`, and triggers `sync_github` on the victim's stack. [1](#0-0) [5](#0-4)

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

**File:** docs/setup.md (L184-209)
```markdown
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
