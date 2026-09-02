### Title
Signature verification keys on `repository.owner.login` while handlers act on `repository.full_name`, letting a multi-org deployment authenticate as one organization but write to another - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects the GitHub App/secret used to validate the HMAC signature based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON body, while every webhook handler determines which repository/stack to mutate from a separate field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name`. These two attacker-supplied fields are never checked for consistency.

### Finding Description
`verify_signature` resolves the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the per-organization config keyed by that value and builds a `GitHubApp` around whatever `webhook_secret` is configured for it: [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` treats an organization with no configured `webhook_secret` as always-valid: [4](#0-3) 

Meanwhile, every handler (`PushHandler`, `PullRequest::*Handler`, `StatusHandler`, etc.) resolves the *actual* repository/stack to act on from a different JSON field, `repository.full_name`, completely independent of the field used for signature/organization selection: [5](#0-4) [6](#0-5) 

This breaks the intended binding: **organization authenticated == repository written**. In a multi-organization instance (`TOP_LEVEL_GH_KEYS` schema, `secrets.github` keyed by org), if any configured organization lacks a `webhook_secret` (e.g. left blank during onboarding, or an org added for OAuth-only purposes), an attacker can submit a crafted webhook body where `repository.owner.login`/`organization.login` names that unsecured organization (so `verify_webhook_signature` short-circuits to `true` with no real signature required), while `repository.full_name` names a completely different, securely-configured organization's repository. The handler will act on that other organization's stack (e.g. archiving/unarchiving review stacks, updating commit statuses, triggering `GithubSyncJob`, auto-creating teams/users via the `membership` event) with no valid signature from the real owning organization.

### Impact Explanation
This allows an unauthenticated attacker to forge GitHub webhook events against a repository belonging to a securely-configured organization by merely knowing/guessing the name of any other configured organization that has no `webhook_secret`. Depending on which webhook events are wired, this can drive unauthorized state changes tied to deploy/rollback flows (e.g., forged `status`/`check_suite` events feeding `deployable_status`, forged `push` triggering `GithubSyncJob`, forged `pull_request` events archiving/creating review stacks) without possessing any real secret for the targeted repository's organization — i.e., cross-repository/cross-organization writes through a spoofed authentication binding.

### Likelihood Explanation
Exploitability strictly depends on the deployment configuring at least one organization in `secrets.github` without a `webhook_secret`, which the code explicitly tolerates (`return true unless webhook_secret`) rather than rejecting. Given the multi-org schema is a supported, documented configuration path (`TOP_LEVEL_GH_KEYS`, `github_app_config`), and nothing in setup enforces `webhook_secret` presence for every org, this is a realistic misconfiguration this code should defend against but does not — the vulnerability is in the engine's trust binding, not merely a deployment choice, since the field used to pick the verifying secret is never cross-checked against the field used to pick the mutated repository.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive the verifying organization from `repository.full_name`'s owner (not a separately-trusted field), and/or require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`). Additionally, after signature verification, re-validate that the organization used for verification matches the owner of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub config: org `secure-org` (has `webhook_secret` set, owns `secure-org/critical-repo` tracked by Shipit) and org `open-org` (configured for OAuth only, no `webhook_secret` set).
2. POST to `/webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "...": "..." },
  "repository": { "full_name": "secure-org/critical-repo", "owner": { "login": "open-org" } },
  "sender": { "login": "attacker" }
}
```
No `X-Hub-Signature` header (or an arbitrary one) is required.
3. `verify_signature` calls `Shipit.github(organization: "open-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally — request passes.
4. `ClosedHandler#repository` resolves `secure-org/critical-repo` via `Repository.from_github_repo_name(params.repository.full_name)`, and `review_stack.archive!` executes against `secure-org`'s stack — an unauthorized state change on a repository the attacker never proved control over.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
