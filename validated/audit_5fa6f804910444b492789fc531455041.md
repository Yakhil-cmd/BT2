I have enough evidence to write up the finding now.

### Title
Webhook signature verification is keyed to an attacker-controlled organization field while write-side handlers act on an independent, unverified repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate a webhook against using a value taken directly from the untrusted request body, while the handlers that actually mutate Shipit state (sync commits, provision/archive review stacks, close pull requests, etc.) key off a *different* body field that is never cross-checked against the field used for verification.

### Finding Description
`verify_signature` derives the signing organization exclusively from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

That organization name is used to look up which `GitHubApp`/`webhook_secret` config to validate the HMAC against: [3](#0-2) 

Crucially, in `GitHubApp#verify_webhook_signature`, when an organization's `webhook_secret` is unset, verification is bypassed unconditionally: [4](#0-3) 

`webhook_secret` is explicitly documented and shipped as optional/nil in every reference config (`docs/setup.md`, `config/secrets.development.example.yml`, `template.rb`, `test/dummy/config/secrets_double_github_app.yml`), and Shipit natively supports multiple organizations sharing one instance (`docs/setup.md` "Using Multiple Github Applications"). Once `verify_signature` passes (trivially, for any org with no secret configured), `create` parses the full body and dispatches it to handlers: [5](#0-4) 

Those handlers resolve the *repository they act on* from a completely separate JSON field, `repository.full_name`, never reconciled with the `repository.owner.login`/`organization.login` value used for signature selection: [6](#0-5) 

For example the push handler triggers a real sync of arbitrary tracked stacks based solely on this unverified field: [7](#0-6) 

Equality broken: `organization whose (possibly-blank) secret authenticated the request` should equal `organization owning the repository the handler mutates`, but the code only checks/uses the former for authentication and the latter for the actual write, with no binding between them.

### Impact Explanation
An unprivileged attacker who knows any organization name configured on the instance (organization names/slugs are public on GitHub) can set `repository.owner.login` (or `organization.login`) in the webhook JSON to that org. If that org's `webhook_secret` happens to be unset (the shipped/documented default), `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header or body content. The attacker then sets `repository.full_name` (and other handler-relevant fields such as `ref`, `after`, `pull_request`, `action`, `sha`, `state`) to target any repository/stack actually tracked by the Shipit instance, including ones belonging to a fully-secured, different organization. This lets the attacker trigger `GithubSyncJob` syncs, pull-request open/close/label review-stack provisioning/archival, commit status writes, and membership/team changes for stacks they have no access to - an unauthorized, cross-organization write into Shipit's deploy pipeline state without ever possessing a valid webhook secret for the targeted repository's real organization.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (a documented, first-class configuration), and (2) at least one configured organization with no `webhook_secret` set - the shipped default in every example/template config in this repository. Given the documented "optional" status of the webhook secret, an admin onboarding a new org (or leaving a low-value org unsecured) is a realistic and anticipated state, not an unsupported deployment.

### Recommendation
Bind the repository actually acted upon to the same trust boundary used for signature verification: verify the signature using the organization derived from `repository.full_name`'s owner (the field handlers actually consume), not a separately-read field; and/or refuse to treat a webhook as verified when the resolved app has no `webhook_secret` configured (fail closed instead of `return true unless webhook_secret`). Additionally, validate that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `OrgA` (properly configured with a `webhook_secret`) and `OrgB` (no `webhook_secret` set, matching the shipped example configs).
2. As an attacker with no credentials, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already reachable in OrgA/target-repo>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/target-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgB")`; since `OrgB`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` for any signature (or none at all).
4. `WebhooksController#create` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("OrgA/target-repo")` and calls `stack.sync_github(expected_head_sha: ...)`, forcing a sync/state change on a stack belonging to `OrgA` even though the request was never signed by `OrgA`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-39)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
