### Title
Cross-organization webhook signature bypass via decoupled `repository.owner.login` (secret selection) and `repository.full_name` (target resolution) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments (a documented, supported configuration), `WebhooksController#verify_signature` selects which GitHub App secret to verify the HMAC signature against using the payload field `repository.owner.login`, while every webhook handler resolves the actual `Stack`/`Repository` to mutate using a *different* payload field, `repository.full_name`. These two fields are never cross-validated. If any configured organization has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` unconditionally returns `true`, letting an attacker forge a payload that "authenticates" as the secret-less org while acting on a completely different, properly-secured organization's repository/stack.

### Finding Description
`WebhooksController#verify_signature` derives the signing key purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` uses that attacker-supplied organization to select a per-org config when multi-org mode is active (`github_default_organization` non-nil, which is true whenever `config/secrets.yml`'s `github` key is org-keyed, per the documented "Using Multiple GitHub Applications" setup): [3](#0-2) 

`GitHubApp#verify_webhook_signature` trivially passes verification if that organization's `webhook_secret` is blank: [4](#0-3) 

Meanwhile, none of the actual webhook handlers use `repository_owner`/the verified organization at all — they resolve the repository/stack to act on from an entirely separate payload field, `repository.full_name`: [5](#0-4) [6](#0-5) 

`PushHandler`, for instance, uses this to sync a real stack to an attacker-chosen commit SHA: [7](#0-6) 

The equality the engine implicitly assumes but never enforces is:
`organization used to select/verify the webhook_secret (repository.owner.login) == organization that owns the repository actually written to (owner segment of repository.full_name)`

Before the attacker's request, this equality holds for genuine GitHub-generated payloads (both fields describe the same repository object). After an attacker submits a crafted payload directly to `POST /webhooks` (this endpoint is unauthenticated by design — it exists to receive GitHub's HTTP callbacks and requires no session, `ApiClient` token, or repository access), the two fields can be independently set: `repository.owner.login` can point at any org configured in the multi-org secrets file with a blank `webhook_secret`, while `repository.full_name` can point at any other org/repo tracked by this Shipit instance.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding explicitly called out as in-scope. Because signature verification is bypassed (via the secret-less org used only for key selection) while the actual mutation target (stack sync to an attacker-supplied SHA, which can cascade into auto-deploy for stacks with continuous deployment enabled) is taken from an unrelated field, this yields an unauthorized cross-organization write/deploy trigger without ever presenting a valid signature for the targeted organization — qualifying as Critical (unauthorized deploy / cross-repository writes).

### Likelihood Explanation
Requires: (1) the host running Shipit in the documented multi-org configuration, and (2) at least one configured organization with no `webhook_secret` set — a state explicitly shown as valid/expected in the shipped example config (`webhook_secret: # nil`). No privileged credentials, sessions, or GitHub App secrets are needed by the attacker; only knowledge of the name of a secret-less configured organization and the target repository's `full_name`, both of which can be discovered or guessed from the Shipit UI (stack listing is typically public/browsable).

### Recommendation
Verify the webhook signature using the same organization that the payload's `repository.full_name` (or `organization.login`) resolves to, and reject the request if `repository.owner.login` and the owner segment of `repository.full_name` disagree. Additionally, do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank in multi-org mode — require every configured organization to define a `webhook_secret`, or fail closed instead of returning `true`.

### Proof of Concept
1. Configure Shipit in multi-org mode with two orgs in `secrets.yml`: `victim-org` (real `webhook_secret`, has a tracked stack for `victim-org/victim-repo`) and `attacker-org` (no `webhook_secret` set, or intentionally left blank).
2. Send, without any GitHub involvement:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef   (arbitrary/garbage)

{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `repository_owner` resolves to `"attacker-org"`; `Shipit.github(organization: "attacker-org")` loads `attacker-org`'s config, whose blank `webhook_secret` makes `verify_webhook_signature` return `true` regardless of the bogus `X-Hub-Signature`.
4. `verify_signature` passes; `PushHandler` runs, resolves `victim-org/victim-repo` via `Repository.from_github_repo_name`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the real victim stack — an unauthorized write/deploy trigger achieved without any valid signature for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
