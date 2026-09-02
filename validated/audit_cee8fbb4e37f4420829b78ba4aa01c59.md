### Title
Webhook signature verification is keyed by an attacker-controlled organization field that is decoupled from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the HMAC against using `repository_owner`, a value read directly from the unauthenticated JSON body. The event handlers that actually mutate state, however, resolve the target repository/stack from a *different* field of the same unauthenticated body (`repository.full_name`). Because these two lookups are never bound to the same, verified identity, an attacker can pick whichever configured GitHub organization has the weakest (or unset) `webhook_secret` to pass verification, while pointing the payload's `repository.full_name` at a completely unrelated, properly-configured repository/stack.

### Finding Description
`repository_owner` is computed purely from request data, before any signature check occurs: [1](#0-0) 

It is fed into `Shipit.github(organization: repository_owner)` to pick a `GitHubApp` config and verify the signature: [2](#0-1) 

`Shipit.github` looks up the app config by the (attacker-supplied) organization key using case-insensitive matching, supporting multiple orgs each with their own `webhook_secret`: [3](#0-2) 

Crucially, `verify_webhook_signature` treats a missing/`nil` `webhook_secret` as automatic success: [4](#0-3) 

Once `verify_signature` passes, the full unauthenticated payload is handed to every registered handler for the event: [5](#0-4) 

But `Handler#stacks`/`#repository_name` resolve the *target* repository from `payload.dig('repository', 'full_name')` - a completely different field than the one used to select the signing organization: [6](#0-5) 

This is the exact binding break required: **the organization whose secret authenticated the request ≠ the repository the handlers act on**. Handlers such as `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), and `CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) all operate on stacks/commits found via `repository.full_name`, independent of which organization's secret validated the signature.

Multi-organization deployments are a supported, documented configuration (`test/dummy/config/secrets_double_github_app.yml`), and it is common for a webhook secret to be left unset (`webhook_secret: null` appears in both `secrets.test.json` and `secrets_double_github_app.yml` as the shipped default). Any single organization in the fleet with `webhook_secret` unset is sufficient to defeat verification for events targeting *any other* repository in the whole installation, because `repository_owner` (used only for the signature check) and `repository.full_name` (used for the actual write) are independent, unauthenticated fields in the same attacker-controlled JSON body.

### Impact Explanation
Using an org with no `webhook_secret` to trivially pass `verify_signature`, an attacker can forge:
- `push` events causing `stack.sync_github` to run for an arbitrary tracked repository/stack, injecting a chosen `expected_head_sha` and forcing `GithubSyncJob` to run against the target org's real credentials (`app/jobs/shipit/github_sync_job.rb:18-49`).
- `status` events, calling `Commit#create_status_from_github!` for any commit sha the attacker names, forging CI status on commits belonging to a repository entirely unrelated to the organization used for verification. Forged "success" statuses can satisfy `required_statuses`/`blocking_statuses` gates used to determine deployability, enabling an unauthorized deploy of a commit that never actually passed CI.
- `membership` events, creating/mutating `Team`/`User` membership records tied to an arbitrary `organization.login` claimed in the payload (`app/models/shipit/webhooks/handlers/membership_handler.rb`), since that org value is likewise never checked against the org that authenticated the request.

This crosses the "unauthorized deploy" and "escalation into `Shipit.github_teams` authorization" impact categories without requiring any Shipit session, API token, or the real target's webhook secret - only knowledge that some organization in the fleet has a weak/unset secret.

### Likelihood Explanation
Requires: (a) a multi-organization Shipit deployment, and (b) at least one configured organization with `webhook_secret` unset or guessable. Both conditions are plausible in real deployments given the documented multi-org support and the fact that `webhook_secret` is explicitly optional in `docs/setup.md`. No credentials, sessions, or GitHub write access are needed by the attacker; only the ability to POST to the public `/webhooks` endpoint.

### Recommendation
Bind the signature-verification identity to the same repository/organization the handlers subsequently act on: derive `repository_owner` only after verifying the signature against the organization that the *target repository* (as resolved by `Repository.from_github_repo_name`) actually belongs to, rather than trusting an unauthenticated field to choose which secret to check against. At minimum, reject webhooks where `repository.owner.login` does not match the owner of the `Repository` record identified by `repository.full_name`, and disallow silently-passing verification when `webhook_secret` is blank in any multi-org configuration.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (webhook_secret unset) and `OrgB` (real webhook_secret, hosts the real tracked repo `OrgB/target-repo`).
2. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature` (or any junk signature):
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "sha": "<real commit sha under CI review in OrgB/target-repo>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` computes `repository_owner = "OrgA"`, loads `OrgA`'s `GitHubApp`, and because `OrgA.webhook_secret` is nil, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
4. `StatusHandler#process` looks up commits by `sha` (matching `OrgB/target-repo`'s tracked commit) and calls `create_status_from_github!`, forging a passing CI status that can unblock deployment of that commit - despite the request never being signed by `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
