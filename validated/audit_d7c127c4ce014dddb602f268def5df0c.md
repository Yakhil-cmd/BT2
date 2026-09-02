## Analog Vulnerability Found

### Title
Webhook signature is validated against the claimed organization's secret while the mutated repository is selected from an unpinned payload field, allowing cross-organization writes with only one org's webhook secret - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and thus which HMAC secret) to validate the incoming webhook against using `repository_owner`, a field read directly from the untrusted JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Once the signature check passes, every event handler (`PushHandler`, `PullRequest::*Handler`, etc.) independently re-reads an *unrelated* field, `payload.dig('repository', 'full_name')`, to locate the `Repository`/`Stack` that will actually be mutated. Nothing ties the `owner.login` used for signature verification to the `owner` half of `full_name` used for the write.

### Finding Description
The controller flow is:
1. `verify_signature` calls `Shipit.github(organization: repository_owner)` to fetch the per-organization `GitHubApp`, then calls `github_app.verify_webhook_signature(signature, raw_post)` which HMACs the *entire raw body* with that organization's `webhook_secret`. [1](#0-0) [2](#0-1) 

2. `verify_webhook_signature` performs a constant-time comparison of the signature against `HMAC(webhook_secret_for(org), raw_post)` — it validates that the body was signed by *some org's* secret, not that the body's contents are internally consistent. [3](#0-2) 

3. Every handler (`Handler#stacks`, and each `pull_request/*` handler) resolves the target `Repository` using `payload.dig('repository', 'full_name')`, a completely separate JSON path from `repository.owner.login`. [4](#0-3) [5](#0-4) 

4. `Repository.from_github_repo_name` blindly splits `full_name` on `/` and looks up any repo row by `owner`/`name`, with no constraint that `owner` matches the organization whose secret validated the request. [6](#0-5) 

5. Shipit explicitly supports multiple organizations, each with its own `webhook_secret`, resolved via `Shipit.github_app_config(organization)`/`Shipit.github(organization:)`. [7](#0-6) 

**Binding that should hold:** `organization authenticated by signature == owner(repository written)`. **Binding that actually holds:** `organization used to pick secret == payload["repository"]["owner"]["login"]` (an attacker-controlled string) while `repository written == payload["repository"]["full_name"]` (a second, independently attacker-controlled string). Because both fields are inside the HMAC-signed body, an attacker with legitimate webhook access to *one* configured organization (e.g., they administer a repo under `org-a` and can push/label/open PRs there to naturally trigger GitHub-signed webhooks, or otherwise possess `org-a`'s `webhook_secret` from that legitimate integration) can also craft `repository.owner.login = "org-a"` (so the correct secret is selected and the signature validates) while setting `repository.full_name = "org-b/other-repo"`. The signature check only proves the body was signed with `org-a`'s secret — it does not prove `full_name` actually belongs to `org-a`.

This is only exploitable through a channel the attacker already legitimately controls (a webhook they can cause GitHub to sign, or a secret they legitimately hold for `org-a`), but it lets them target and mutate stacks/repositories belonging to a completely different, unrelated organization (`org-b`) registered in the same Shipit instance — an unauthorized cross-repository/cross-organization write.

### Impact Explanation
This matches the "Critical: cross-repository writes" bucket. With a forged `full_name`, an attacker who only controls one organization's signing context can:
- Trigger `PushHandler` → `stack.sync_github` on stacks belonging to a repository owned by a different organization.
- Trigger `pull_request` handlers (`opened`, `labeled`, `closed`, etc.) to archive/unarchive review stacks, or mutate `PullRequest` records tied to a different org's repositories.

Because Shipit is explicitly built to host multiple organizations behind one instance (`Shipit.github_organizations`), this is a cross-tenant boundary violation, not merely a self-inflicted misconfiguration.

### Likelihood Explanation
Requires the attacker to already have a legitimate webhook relationship (and therefore the shared secret) with at least one organization configured in the same Shipit instance, and for that instance to host multiple organizations. This is a real, supported deployment topology (per-organization `github` secrets block in `secrets.yml`), so the precondition is plausible in multi-tenant Shipit deployments, though it does not affect single-organization deployments (`github_default_organization.nil?` case, where there is only one global secret and this owner/full_name split is moot).

### Recommendation
When validating an incoming webhook, require that the organization used to select the verifying secret matches the owner segment of `repository.full_name` (or `organization.login`) exactly, and reject (422) any payload where these are inconsistent, e.g.:
```ruby
def verify_signature
  claimed_owner = repository_owner
  full_name_owner = params.dig('repository', 'full_name')&.split('/', 2)&.first
  return head(422) if full_name_owner.present? && full_name_owner.casecmp(claimed_owner) != 0
  # ... existing signature verification
end
```
This restores the invariant that the organization whose secret authenticated the request is the same organization that owns the repository being written.

### Proof of Concept
1. Shipit instance is configured with two organizations, `org-a` and `org-b`, each with a distinct `webhook_secret` (per `lib/shipit.rb#github_app_config`).
2. Attacker has legitimate access to trigger/observe a correctly GitHub-signed webhook for a repo under `org-a` (e.g., they open a PR on `org-a/some-repo`, causing GitHub to sign the payload with `org-a`'s configured secret) — or otherwise legitimately holds `org-a`'s `webhook_secret`.
3. Attacker crafts (or replays with modification, if they control the secret) a JSON body:
```json
{
  "action": "closed",
  "number": 42,
  "pull_request": { ... },
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/target-repo" },
  "sender": { "login": "attacker" }
}
```
4. Signs it with `org-a`'s `webhook_secret`, sets `X-Hub-Signature`, POSTs to `/github/webhooks`.
5. `verify_signature` resolves `Shipit.github(organization: "org-a")` and the HMAC matches → request passes. [1](#0-0) 
6. `ClosedHandler#repository` resolves `Repository.from_github_repo_name("org-b/target-repo")`, and `review_stack.archive!` executes against `org-b`'s stack despite the request only ever being authenticated for `org-a`. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
