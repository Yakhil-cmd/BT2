### Title
Webhook signature verification is keyed off an unauthenticated payload field, decoupling the "organization that authenticated" from the "repository that is written" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to validate the HMAC signature against by reading an unauthenticated field from the still-unverified JSON body (`repository.owner.login` / `organization.login`), rather than binding the verification to a value that is guaranteed to match what the downstream handler subsequently uses to identify which `Repository`/`Stack` the payload is written to (`repository.full_name`). Combined with `GitHubApp#verify_webhook_signature` trivially returning `true` whenever a given organization has no `webhook_secret` configured, an attacker can construct a single payload where the "authenticating" organization and the "acted-upon" repository are different entities, breaking the equality that the signature is supposed to enforce: `organization verified via signature == organization of the repository actually mutated`.

### Finding Description
`verify_signature` picks the GitHub App config to validate against using a field taken straight from the raw, not-yet-verified request body: [1](#0-0) [2](#0-1) 

That organization is resolved through `Shipit.github(organization:)`, which supports a genuine multi-organization configuration schema (`github_organizations`, `github_app_config`): [3](#0-2) 

Signature verification itself is a no-op whenever the resolved organization has no `webhook_secret` configured: [4](#0-3) 

Once `head(422)` is not triggered, `WebhooksController#create` dispatches the *entire, attacker-controlled* JSON body to the event handlers unchanged: [5](#0-4) 

Handlers then resolve the actual `Repository`/`Stack` to mutate from a *different* field of the same payload — `repository.full_name` — which is never re-checked against the organization that was used for signature verification: [6](#0-5) [7](#0-6) 

Because `repository.owner.login` (used to pick the verifying org/secret) and `repository.full_name` (used to pick the mutated repository/stack) are two independent fields inside the same untrusted JSON body, they need not agree. If any organization configured on the instance has `webhook_secret` unset/blank (a supported, non-error configuration state — see the shipped `null` value in `test/dummy/config/secrets.test.json`), an attacker who merely knows that organization's *name* (not its secret) can craft a payload with `repository.owner.login` set to that no-secret org (so `verify_webhook_signature` short-circuits to `true`) while setting `repository.full_name`/`pull_request.head.ref`/etc. to point at an entirely different, secret-protected repository. The signature check "authenticates" org A, but the handler code writes to repo/org B.

### Impact Explanation
This breaks the deployment-trust binding between the organization whose credentials were verified and the repository that is actually acted upon. Depending on the handler reached, this can drive unauthenticated triggering of `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb`), creation/deletion of review stacks (`PullRequest::OpenedHandler`, `ReopenedHandler`), or other repository/stack state transitions for a repository the attacker has no legitimate signing capability for — i.e., a cross-organization/cross-repository write performed under the guise of a signature check that never actually covered the acted-upon repository.

### Likelihood Explanation
Requires an instance configured with more than one GitHub organization where at least one has no `webhook_secret` set — a state the engine explicitly permits (`return true unless webhook_secret`) rather than rejecting. No GitHub App private key, `webhook_secret`, `api_clients_secret`, session, or repository write access is needed; the attacker only needs the raw endpoint URL and the name of the unsecured organization, which is realistic for staging/multi-tenant setups or during secret rotation.

### Recommendation
Bind signature verification to the same identity used for downstream repository resolution: derive the verifying organization from `repository.full_name`'s owner segment (not a separately-trusted field), and refuse to process (or clearly warn/alert on) any organization configured without a `webhook_secret` rather than silently treating it as "verified". Additionally, after signature verification succeeds, re-validate that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure `secrets.github` with two organizations: `org-a` (no `webhook_secret`) and `org-b` (a `webhook_secret` set, hosting a real tracked Stack).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<sha>",
  "repository": { "full_name": "org-b/target-repo", "owner": { "login": "org-a" } }
}
```
3. `verify_signature` computes `repository_owner == "org-a"`, resolves `Shipit.github(organization: "org-a")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `create` proceeds to dispatch the push handler, which resolves the target repository from `repository.full_name == "org-b/target-repo"` and enqueues `GithubSyncJob` for `org-b`'s stack — a write the attacker was never able to sign for.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
