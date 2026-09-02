### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate an inbound webhook's HMAC against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')` as fallback). All downstream event handlers, however, resolve the target `Repository`/`Stack` to act on using a completely different payload field: `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`. When an organization is configured with no `webhook_secret` (an explicitly supported, documented configuration - see `webhook_secret: # nil` in `test/dummy/config/secrets_double_github_app.yml`), signature verification for that organization becomes a no-op, letting anyone submit a forged payload that claims `repository.owner.login`/`organization.login` for the secret-less org while setting `repository.full_name` to a different, secret-protected organization/repository that Shipit tracks.

### Finding Description
The binding that should hold is: *the organization whose secret authenticated the request* == *the organization/repository whose state the handler mutates*. This engine breaks that equality.

- `verify_signature` looks up the app config via the owner/organization field only: [1](#0-0) [2](#0-1) 

- `verify_webhook_signature` trivially returns `true` when the resolved organization has no configured `webhook_secret`: [3](#0-2) 

- Multiple organizations, each with their own (possibly blank) `webhook_secret`, are a documented, supported configuration: [4](#0-3) [5](#0-4) 

- Once past `verify_signature`, every handler (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`, `CheckSuiteHandler`, etc.) resolves the affected repository purely from `repository.full_name`, never re-checking `repository.owner.login` against the organization that was actually authenticated: [6](#0-5) [7](#0-6) [8](#0-7) 

This is the same bug class as the referenced report: a value that is checked/paid against one identity (there: the fee tied to registration outcome; here: the HMAC tied to `repository.owner.login`) is not the value actually consumed/acted upon (there: the refunded stake; here: `repository.full_name` used to pick the mutated `Stack`/`Repository`/`Commit`). The signature check authenticates one field of the payload's identity while the write path trusts an unrelated field of the same, otherwise-unauthenticated body.

### Impact Explanation
An unprivileged attacker who knows only that some configured organization in the target Shipit instance has no `webhook_secret` (this is discoverable/likely for lower-security orgs, and is an explicitly supported "nil" config) can:
1. Send a POST to `/webhooks` with `X-Github-Event` set to `push`, `status`, `pull_request`, or `check_suite`.
2. Set `repository.owner.login`/`organization.login` to the secret-less organization so `verify_signature` passes unconditionally.
3. Set `repository.full_name` to any other tracked repository (belonging to a *different*, secret-protected organization).
4. Trigger unauthorized actions against that other repository/stack without ever presenting a valid signature for it - e.g. forging commit statuses via `StatusHandler#process` → `Commit#create_status_from_github!` (which can be used to satisfy CI-gated deploy conditions), forcing GitHub syncs via `PushHandler`, or manipulating pull-request state/labels used for review-stack provisioning via the `PullRequest::*Handler` classes.

Given that commit statuses can gate whether a `Stack` is eligible for deploy, this can escalate into unauthorized deploy triggering conditions being satisfied by a party with no legitimate access to the target repository or its webhook secret - matching the "escalation into authorization"/"unauthorized deploy" impact classes.

### Likelihood Explanation
Likelihood is moderate: it requires (a) the Shipit instance to be configured with at least one organization lacking `webhook_secret` (documented as valid, but an operational choice, not the default single-org path) and (b) the attacker to guess/know a tracked `repository.full_name` for a different org, which is often public information (GitHub repo names are public). No credentials, tokens, or session are required - only the ability to POST to the public `/webhooks` endpoint, which is unauthenticated by design.

### Recommendation
Bind signature verification to the same identity the handlers act on. Concretely, `Shipit::Webhooks::Handlers::Handler` should re-validate that the `Repository` resolved via `repository.full_name` actually belongs to the organization that was used to select the `webhook_secret` in `WebhooksController#verify_signature` (or, simpler, have `verify_signature` resolve the organization from `repository.full_name`'s owner rather than `repository.owner.login`, so a single field drives both signature-org selection and the write target). Additionally, consider rejecting/logging when an organization has no `webhook_secret` configured but is used to short-circuit verification for a payload referencing a differently-owned repository.

### Proof of Concept
1. Configure two organizations in `secrets.github`: `OrgA` (has `webhook_secret: real-secret`, owns tracked repo `OrgA/private-repo`) and `OrgB` (has `webhook_secret: nil`).
2. Attacker (no credentials) POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<any tracked commit sha in OrgA/private-repo>",
  "state": "success",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/private-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank for `OrgB` (`lib/shipit/github_app.rb:76-77`), regardless of the actual `X-Hub-Signature` header value (or its absence).
4. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which resolves the commit purely by `sha` and calls `Commit#create_status_from_github!(params)`, writing an attacker-controlled CI status onto a commit belonging to `OrgA/private-repo` - despite never having presented a valid signature for `OrgA`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
