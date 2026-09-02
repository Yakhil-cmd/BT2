### Title
Webhook Signature Verified Against `repository.owner.login` While Target Repository Is Resolved From The Independent `repository.full_name` Field, Enabling Cross-Organization Writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / HMAC secret to validate a webhook against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`). Every webhook handler instead resolves the record it actually mutates (`Stack`, `Commit`, etc.) via `Handler#repository_name`, which reads a *different* field of the same body — `payload.dig('repository', 'full_name')` — without ever checking that it is consistent with the owner used for signature verification. In multi-organization Shipit deployments (`Shipit.github(organization:)` / `github_app_config`), this breaks the binding "organization whose secret authenticated the request == repository the request is allowed to write to."

### Finding Description
`WebhooksController` computes the signing organization purely from body content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization webhook secret from `secrets.github` in the multi-org configuration: [3](#0-2) 

`verify_webhook_signature` then HMAC-validates the raw body using that org's secret: [4](#0-3) 

Once the signature check passes, every handler resolves the actual target repository/stack from a **different** field of the same body: [5](#0-4) 

For example, `PushHandler` triggers `sync_github` on every non-archived `Stack` whose `Repository` matches `full_name`: [6](#0-5) 

`StatusHandler` writes commit statuses for any `Commit` matching the SHA, again scoped only by data inside the same body: [7](#0-6) 

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the mutated repository) are two independent JSON fields inside the same signed payload — nothing forces them to reference the same organization. Because the signature only proves "this exact byte string was signed with organization X's secret," an org that legitimately possesses its own configured webhook secret (a normal, unprivileged Shipit tenant in a multi-org config) can craft a body where `repository.owner.login = "org-x"` (so `verify_signature` resolves and matches org X's secret) but `repository.full_name = "org-y/some-repo"` (a different, victim organization's repository also onboarded on the same Shipit instance).

Before the attack: an event for `org-y/some-repo` can only be produced by GitHub itself, signed with org Y's own webhook secret, and legitimately reflects `org-y`'s repository state.

After the attack: `verify_signature(org-x's secret) == true` while `Handler#repository_name == "org-y/some-repo"`, i.e. `organization_that_authenticated ≠ repository_that_is_written`. The equality the engine relies on for trust is broken.

### Impact Explanation
An org configured in a multi-tenant Shipit deployment can push forged `push`, `status`, `check_suite`, or `membership` events that get accepted as authentic for a completely different organization's repositories/stacks, because signature verification and target-resolution are keyed by two unrelated fields of the same attacker-supplied JSON body. This can trigger unauthorized `sync_github` calls, poison commit statuses/check runs used to gate deploys (`Commit#create_status_from_github!`), or otherwise influence deploy readiness state for a stack that belongs to a different organization — a cross-repository write outside the attacker's own GitHub permissions. This lands squarely in the "cross-repository writes" / "unauthorized deploy" impact category since commit statuses and check-run state feed directly into whether a stack is considered deployable.

### Likelihood Explanation
Exploitation requires only that the attacker legitimately control one organization already configured in Shipit's multi-org `secrets.github` mapping (a normal unprivileged tenant, not a privileged Shipit account or GitHub App private key holder) and be able to send an arbitrary POST to `/webhooks` with a body they sign themselves using their own known secret. No session, `ApiClient` token, or GitHub App private key for the victim org is needed. This is a realistic, low-effort exploitation path in any deployment using the "Using Multiple GitHub Applications" configuration documented for Shipit.

### Recommendation
After successfully verifying the webhook signature, re-derive the organization from the *same* field used to route to a repository (`repository.full_name`'s owner segment) and reject the request if it doesn't match the organization whose secret validated the signature. Alternatively, always resolve the signing organization and the acted-upon repository from a single, consistent field, and add an explicit equality check between `repository_owner` and the owner portion of `full_name` before invoking any handler.

### Proof of Concept
1. Configure Shipit with multi-org secrets for `org-x` (attacker-controlled) and `org-y` (victim), each with their own GitHub App and `webhook_secret`, both onboarded with stacks in Shipit.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-x" },
    "full_name": "org-y/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-x_webhook_secret, body)>` using their own legitimately known secret for `org-x`.
4. POST to `/webhooks` with header `X-Github-Event: push`. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-x")` and verifies successfully against `org-x`'s secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-y/victim-repo")` and calls `sync_github` on `org-y`'s stacks, despite the request never being signed by `org-y`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
