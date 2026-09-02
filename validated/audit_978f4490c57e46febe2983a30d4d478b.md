### Title
Webhook Signature Is Verified Against the Payload's `repository.owner.login`, but Event Handlers Act on the Payload's `repository.full_name` — Cross-Organization Stack Spoofing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a request against by reading the *unauthenticated* `repository.owner.login` (or `organization.login`) field out of the JSON body itself, then validates the HMAC signature of the raw body using that organization's secret. Once verification passes, the *same* untrusted body is handed to event handlers (e.g. `PushHandler`), which pick the `Stack`/`Repository` to act on using a *different* field of the same body — `repository.full_name`. In a multi-tenant Shipit deployment (multiple GitHub orgs configured via `Shipit.github_app_config`), these two fields are never cross-checked, so a party who legitimately knows only one organization's webhook secret can produce a validly-signed payload whose `repository.owner.login` matches their own org (to pass signature verification) while `repository.full_name` names a repository/stack belonging to a different organization tracked by the same Shipit instance.

### Finding Description
- `WebhooksController#verify_signature` derives `repository_owner` purely from the request body: [1](#0-0) 
  It uses that value to fetch the per-organization `GitHubApp` (and thus the per-organization `webhook_secret`) and verifies the raw body's `X-Hub-Signature` against it: [2](#0-1) 
- `Shipit.github` resolves a distinct `GitHubApp`/secret per organization when the credentials file is keyed by organization name: [3](#0-2) 
- Once the signature check passes, `create` parses the same raw body and dispatches it, unmodified, to the registered handlers for the event: [4](#0-3) 
- `PushHandler`, however, determines which stacks to act on from `params.ref`/`params.after` combined with the `Handler` base class's repository resolution, which is driven by `repository.full_name` (as seen consistently across handlers, e.g. `OpenedHandler#repository`): [5](#0-4) [6](#0-5) 

The binding that is broken is: **organization authenticated (`repository.owner.login` used to pick the verifying secret) == repository that is written (`repository.full_name` used by the handler to select the `Stack`/`Repository`)**. Nothing in `verify_signature` or in the handlers enforces that the `full_name`'s owner segment matches the `owner.login` that was used to select the verifying secret. Both values come from the same attacker-controlled JSON body, so an attacker only needs to control the pairing between them, not defeat any cryptography.

### Impact Explanation
In a Shipit deployment configured for multiple GitHub organizations (`Shipit.github_organizations`, `github_app_config`), any party who legitimately holds the webhook secret for organization A (e.g., because they administer org A's GitHub App/webhook settings on the shared Shipit install) can forge a signed webhook body where:
- `repository.owner.login = "org-a"` (so `verify_signature` selects org A's secret and validates the HMAC over the full raw body, which the attacker computed themselves with the known secret), and
- `repository.full_name = "org-b/some-repo"` (a repository/stack belonging to a different, unrelated organization hosted on the same instance).

This body reaches `PushHandler`, which syncs the head SHA / branch of `org-b/some-repo`'s stack and can trigger `GithubSyncJob` / downstream deploy pipeline processing for a repository the attacker does not control. Other handlers keyed off `repository.full_name` (pull-request review-stack provisioning/archival, label capture, etc.) are equally exposed. This is a cross-organization/cross-repository write within the app's own trust model — an org that only proved control of its own webhook secret can influence another org's tracked stacks, meeting the "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Exploitability requires only:
1. A Shipit instance configured for more than one GitHub organization (a supported, documented configuration via `github_app_config`), and
2. Possession of the legitimate webhook secret for any one of those organizations (which that organization's own administrators necessarily have, since they configure the webhook in their own GitHub App/organization settings).

No compromise of Shipit sessions, `ApiClient` tokens, or GitHub credentials for the *target* organization is required — only knowledge of a secret the attacker's own (unrelated) organization already legitimately possesses. This is a realistic likelihood for any multi-tenant Shipit install.

### Recommendation
After signature verification succeeds, bind the authenticated `repository_owner` to the identity actually used by the handlers: verify that `params.dig('repository', 'full_name')&.split('/')&.first` (case-insensitively) equals the `repository_owner`/organization used to select the verifying secret before dispatching to handlers, and reject (422) on mismatch. Alternatively, pass the authenticated organization explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, organization: repository_owner) }` and have `Handler#repository`/`#stacks` resolve strictly within that authenticated organization rather than trusting `repository.full_name` alone.

### Proof of Concept
Assume a Shipit instance with `secrets.github` configured for two orgs, `org-a` and `org-b`, each with its own `webhook_secret`. An operator of `org-a` (who legitimately knows `org-a`'s webhook secret because they manage `org-a`'s GitHub App settings) can:

1. Build a push payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
2. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a-webhook-secret, body)>`.
3. POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "org-a"`, fetches org-a's `GitHubApp`, and validates the signature successfully (the attacker computed it with the secret they legitimately know) — see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
5. `create` dispatches the parsed body to `PushHandler`, which resolves the target stack(s) via `repository.full_name = "org-b/victim-repo"` (see `app/models/shipit/webhooks/handlers/push_handler.rb:1-27` and the repository-resolution pattern shared across handlers, e.g. `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`), enqueuing `GithubSyncJob` for a stack that belongs to `org-b`, an organization the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
