### Title
Cross-organization webhook signature substitution allows forging events for a repository outside the authenticating organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports per-GitHub-organization app configuration, each with its own independent `webhook_secret`, resolved via `Shipit.github(organization: repository_owner)` [1](#0-0) . The webhook signature check picks which organization's secret to verify against solely from `repository.owner.login` (or `organization.login`) inside the same untrusted JSON payload [2](#0-1) [3](#0-2) . Downstream handlers, however, resolve the actually-affected repository from a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name` [4](#0-3) .

### Finding Description
The binding that should hold is: `organization whose secret authenticated the request == organization that owns the repository the handler mutates`. Instead, the controller selects the verifying secret using `repository.owner.login`, while `PushHandler`, `StatusHandler`, and other handlers select the target `Repository`/`Stack` using the independent `repository.full_name` field [5](#0-4) , and `Repository.from_github_repo_name` performs a plain owner/name DB lookup with no cross-check against the org used for signature verification [6](#0-5) .

Because both `owner.login` and `full_name` are attacker-controlled fields within the single HMAC-signed body, an actor who knows the `webhook_secret` configured for *their own* GitHub organization (which they legitimately configured on GitHub's webhook settings page for their own org integration) can craft a payload where:
- `repository.owner.login = "attacker-org"` — causing `verify_signature` to fetch and validate against `attacker-org`'s webhook secret, which the attacker knows and can correctly HMAC-sign.
- `repository.full_name = "victim-org/victim-repo"` — an entirely different repository/organization, which is what `Handler#repository_name` and thus `Repository.from_github_repo_name` actually operate on.

Since `OpenSSL::HMAC` in `verify_webhook_signature` is computed over the full `request.raw_post` [7](#0-6) , the signature is technically "valid" for the exact bytes sent — but it only proves the payload came from someone who knows *attacker-org*'s secret, not that the events inside pertain to `attacker-org`'s repos. The controller never checks that `repository.owner.login == repository.full_name`'s owner segment, nor that the org used to fetch the verifying secret is the same org that owns the stack being manipulated.

This is a direct analog of the underlying "price used to gate an action was never the value verified" bug class: here, the field used to select/verify the authenticating credential (`owner.login`) is disjoint from the field used to select the object being mutated (`full_name`).

### Impact Explanation
Handlers driven by this event allow real state mutation on a repository the attacker does not control: `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any matching branch on the "spoofed" `full_name` repo/stacks [8](#0-7) , and `StatusHandler` writes CI status records against arbitrary commits found by SHA regardless of which org's secret authenticated the request [9](#0-8) . Forcing a resync onto an unexpected `expected_head_sha` or injecting spoofed CI status could influence deploy readiness checks and mergeability signals for a repository the attacker does not administer — a cross-repository state write performed without holding write access to the victim's GitHub repository, matching the Critical "cross-repository writes" bar, though it does not directly execute arbitrary deploy commands.

### Likelihood Explanation
This requires (a) the Shipit instance to be multi-tenant, configuring more than one GitHub organization each with a distinct `webhook_secret` (a supported, documented configuration per `TOP_LEVEL_GH_KEYS`), and (b) the attacker to control (or already be a legitimate integrator for) at least one of those configured organizations so they know its `webhook_secret`. This is a realistic scenario for a shared/multi-tenant Shipit deployment serving several GitHub orgs, where each org's admin is trusted only for their own org's webhooks but not for others'.

### Recommendation
After selecting the webhook secret via `repository_owner`, additionally assert that the payload's `repository.full_name` owner segment (and/or `organization.login`) matches `repository_owner` before dispatching to handlers, rejecting the request with 422 otherwise. This restores the invariant that the organization whose secret authenticated the request is the same organization whose repository is mutated.

### Proof of Concept
1. Shipit is configured with two orgs, `attacker-org` (secret `S_A`, known to the attacker) and `victim-org` (secret `S_V`, unknown to attacker).
2. Attacker crafts a `push` payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, body)>` using their known `attacker-org` secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"` from `params.dig('repository','owner','login')`, fetches `Shipit.github(organization: 'attacker-org')`, and successfully verifies the signature against `S_A` [2](#0-1) .
5. `PushHandler#process` runs, calling `Handler#repository_name`, which reads `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, looks up that `Repository`/its `Stack`s, and triggers `sync_github(expected_head_sha: params.after)` on the victim's stacks [8](#0-7)  — despite the request never being authenticated by `victim-org`'s secret.

### Citations

**File:** lib/shipit.rb (L170-180)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
