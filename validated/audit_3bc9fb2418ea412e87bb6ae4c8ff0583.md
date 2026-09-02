## Analysis

I found a concrete instance of the bug class described in the report: a value used to authenticate/authorize a payload differs from the value that determines what is actually written, allowing an attacker to smuggle a mismatched field through signature verification.

### Title
Webhook signature verified against the requesting organization's secret while the write path trusts an unrelated repository field from the same unauthenticated JSON body - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC secret) to validate the signature against using `repository_owner`, computed from the raw, not-yet-verified JSON body. Once verification succeeds, `WebhooksController#create` dispatches the *entire* payload to handlers (e.g. `PushHandler`), which independently derive the target `Stack`/`Repository` using a *different* field, `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. In a multi-organization deployment (`Shipit.github_organizations` / per-organization `webhook_secret` in `TOP_LEVEL_GH_KEYS`), these two lookups are not bound together by the signature check.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` (line 59-62) is:
```ruby
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```
This selects which per-organization `webhook_secret` (configured under `Shipit.github_app_config(organization)`, `lib/shipit.rb:196-200`) is used to HMAC-verify the raw body. The signature check only proves that *someone who knows Organization A's webhook secret* produced this exact raw body — it says nothing about which repository the payload's handlers will actually act on.

After `head(422) unless verified` passes, `create` (lines 10-15) does:
```ruby
params = JSON.parse(request.raw_post)
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
```
Handlers such as `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb`) resolve the target stacks through `Handler#stacks`/`#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`):
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`repository.full_name` and `repository.owner.login` are two independently attacker-controllable fields inside the same JSON body; nothing in the controller or `Repository.from_github_repo_name` enforces that `full_name`'s owner segment matches `repository.owner.login`. Because the HMAC covers the whole raw body, an attacker cannot forge an *arbitrary* body without the secret — but an attacker who legitimately possesses (or leaks) Organization A's `webhook_secret` (e.g. a compromised low-privilege integration on their own org, which is the realistic "unprivileged" holder of a webhook secret for their own repo) can freely author both fields before signing, setting `repository.owner.login` to their own org (so `Shipit.github(organization: "orgA")` picks their secret and verification passes) while setting `repository.full_name` to `"orgB/some-repo"` for a *different* organization's stack that Shipit also manages, and sign the whole body with their own `orgA` secret. Because `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) blindly `find_by(owner:, name:)` without checking `repository.owner.login`, `PushHandler` will happily call `stack.sync_github` / dispatch cross-organization mutating actions (`sync_github`, status creation, `check_suite` refresh, merge-request processing, review-stack provisioning/archival, membership/team management, etc.) against the `orgB/some-repo` stack, using Organization A's key merely as the "ticket" to pass verification.

This is the direct analog of the reported issue's core defect: a binding that should be `authenticated_scope == acted_upon_scope` is broken because the code verifies against one field (`repository.owner.login`, selecting the secret) but performs the mutating action keyed on a different, unchecked field (`repository.full_name`) from the same unverified-at-check-time body.

### Impact Explanation
This allows a party who legitimately holds a webhook secret for one organization/repository configured in this Shipit instance to trigger writes against stacks belonging to a *different* organization that they have no authorization for — e.g. forcing `GithubSyncJob`, review-stack archive/unarchive, membership/team creation, or (for other handlers) actions gated on `repository_name`. This crosses a repository/organization authorization boundary and can produce unauthorized state changes on stacks the attacker does not own, matching the "cross-repository writes" High/Critical impact category.

### Likelihood Explanation
Exploitability requires the deployment to be configured with multiple GitHub organizations (`TOP_LEVEL_GH_KEYS`/per-org `webhook_secret`, as supported by `Shipit.github_app_config`) and requires the attacker to possess a valid webhook secret for at least one of them — a realistic "unprivileged w.r.t. other orgs" position for a multi-tenant Shipit instance, since webhook secrets are typically held by GitHub App/organization admins who are not privileged Shipit users. I was not able to verify from the indexed code alone whether any additional cross-check (e.g. at the Octokit/App-installation level) exists that would reject an installation token mismatch before `Repository.from_github_repo_name` runs; a full verification would require running the multi-org test suite or instrumenting a live instance, which is out of scope for static review here.

### Recommendation
After signature verification succeeds, re-validate that `repository.full_name`'s owner matches the `repository_owner`/organization whose secret was used to verify the signature (or, more robustly, verify signatures against every configured organization's secret and record which org verified, then require handlers to key off that verified org rather than trusting `repository.full_name` independently).

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s (per `TOP_LEVEL_GH_KEYS` schema) and each with at least one `Repository`/`Stack`.
2. As a holder of `orgA`'s webhook secret, craft a JSON push payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and `POST` to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner == "orgA"`, loads `Shipit.github(organization: "orgA")`, and the signature validates successfully against `orgA`'s secret.
5. `create` dispatches the parsed payload to `PushHandler`, which resolves `repository_name == "orgB/target-repo"` and calls `Repository.from_github_repo_name("orgB/target-repo").stacks`, triggering `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `orgB`'s stack — despite the attacker never having proven possession of `orgB`'s webhook secret. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
