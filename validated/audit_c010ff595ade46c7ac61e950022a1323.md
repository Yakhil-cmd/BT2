### Title
Webhook signature verification authenticates the wrong organization, allowing cross-organization stack manipulation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate an inbound webhook using the payload's `repository.owner.login` (or `organization.login`), but the handlers that actually act on the webhook (create/archive/unarchive review stacks, sync commits, etc.) resolve the target `Repository`/`Stack` using a completely different, unauthenticated payload field: `repository.full_name`. Because these two fields are never cross-checked, a webhook that is "authenticated" for one GitHub organization can be crafted to act on a repository/stack belonging to a different organization configured on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the webhook secret) to verify against by reading the organization name straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks the HMAC of the raw body against that organization's own `webhook_secret`; it never verifies that this organization is the same one whose repository is subsequently mutated. Notably, if that organization has no `webhook_secret` configured — an explicitly documented, optional setting (`docs/setup.md` "Webhook secret (optional)"; also shown as a valid blank value in `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`) — verification is bypassed entirely: [3](#0-2) 

Multi-organization support is a first-class, documented feature (`docs/setup.md` "Using Multiple Github Applications"), and each organization's config, including `webhook_secret`, is independent: [4](#0-3) 

Once the request passes (or trivially bypasses) this organization-scoped check, every default webhook handler resolves the `Repository`/`Stack` to act on using a *different* payload field — `repository.full_name` — with no relation enforced back to the organization that was authenticated: [5](#0-4) 

For example, `PushHandler` uses this `stacks` scope directly to trigger a GitHub sync: [6](#0-5) 

And review-stack pull_request handlers resolve `repository` the same way and call lifecycle-mutating actions such as `archive!`/`unarchive!`, which deprovision/reprovision infrastructure: [7](#0-6) [8](#0-7) 

**Trust binding broken:** `organization that authenticated the request` (via `repository.owner.login`/`organization.login` and that org's `webhook_secret`) ≠ `organization/repository whose Stack is actually written` (via `repository.full_name`, an independent, unverified field in the same payload).

### Impact Explanation
An attacker with no credentials for a well-secured organization "OrgA" can forge a webhook payload that is validated using a different, weakly- or un-secured organization "OrgB" (e.g., one onboarded without a `webhook_secret`, which the docs explicitly allow), while setting `repository.full_name` to point at an OrgA-owned repository. This causes the engine to perform state-changing operations against OrgA's `Stack` (e.g., forcing a `sync_github`, or archiving/unarchiving/deprovisioning a review stack, adding it to the `ReviewStackProvisioningQueue`) without ever validating a credential belonging to OrgA. This is a cross-repository write across an organization trust boundary driven purely by unauthenticated JSON fields.

### Likelihood Explanation
Exploitability requires only that at least one organization configured on the shared Shipit instance has no `webhook_secret` set — explicitly called out as "optional" in `docs/setup.md` and shown as a supported blank value in the multi-org example configs. Given that, exploitation requires zero credentials: the `/webhooks` endpoint is intentionally public (it skips CSRF verification and has no session/authentication requirement), and the payload's `repository.full_name` is fully attacker-controlled JSON. Any multi-tenant Shipit deployment where organizations are onboarded incrementally (a very plausible operational pattern) is exposed.

### Recommendation
After successfully verifying the webhook signature for organization X, enforce that every field used by handlers to select the target `Repository`/`Stack` (`repository.full_name`, `repository.owner.login`) is consistent with X. Concretely, in `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`, reject or ignore payloads whose `repository.owner.login` does not match the organization that was actually used to validate the signature (threading that organization through from `WebhooksController` into each handler), rather than trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (has `webhook_secret: strong-secret`, owns `Stack` for `OrgA/prod-app`) and `OrgB` (has no `webhook_secret` set, per the documented optional setting).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/prod-app"
  }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` to `"OrgB"`, calls `Shipit.github(organization: "OrgB").verify_webhook_signature(...)`, which returns `true` unconditionally because `OrgB` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`) — no valid `X-Hub-Signature` header is even required.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgA/prod-app")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on OrgA's stack, even though the request was never authenticated for OrgA.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
