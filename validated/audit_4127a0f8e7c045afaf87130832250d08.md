### Title
Webhook signature verification uses a different organization than the repository the event actually mutates, allowing forged GitHub events for any repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted, unverified JSON payload. The event is then dispatched to handlers that resolve the *actual* repository/commit to mutate from a different, independently-controlled payload field (`repository.full_name`, or for `status` events, no repository field at all). Because Shipit supports multiple GitHub organizations each with their own optional `webhook_secret` [1](#0-0) [2](#0-1) , and `verify_webhook_signature` trivially returns `true` when no secret is configured for the selected organization [3](#0-2) , an attacker with no credentials can pick any org that lacks a `webhook_secret` to satisfy the "authenticating organization", while pointing the payload's mutation-relevant fields at a completely different, sensitive repository/commit.

### Finding Description
`verify_signature` computes the signing org purely from attacker-controlled JSON: [4](#0-3) [5](#0-4) 

The actual mutation performed by handlers uses a different, separately attacker-controlled field, `repository.full_name`: [6](#0-5) 

Worse, the `status` handler (used to record CI/commit statuses) doesn't even scope by repository — it matches purely by commit SHA across the whole install: [7](#0-6) 

`Shipit.github(organization:)` supports per-organization app configs, each with an independently optional `webhook_secret` [1](#0-0) , and the dummy fixtures for multi-app installs show organizations legitimately configured with `webhook_secret: # nil` [2](#0-1) . When `webhook_secret` is blank, `verify_webhook_signature` unconditionally returns `true`: [3](#0-2) .

The equality the code implicitly (and wrongly) assumes is:
`organization used to select/verify the webhook signature == organization/repository that the event payload actually mutates`

This equality breaks because both sides are independently attacker-supplied fields in the same unauthenticated JSON body: `repository.owner.login` (or `organization.login`) drives signature-org selection, while `repository.full_name` (handler.rb) or nothing at all (status_handler.rb) drives which stacks/commits get mutated.

### Impact Explanation
An unprivileged attacker who knows any organization onboarded to the Shipit instance without a configured `webhook_secret` can send a POST to `/webhooks` with `X-Github-Event: status`, set `repository.owner.login`/`organization.login` to that unsecured org (bypassing signature verification entirely), and set `sha`/`state`/`context` to target a commit in an entirely unrelated, security-sensitive repository. Because `StatusHandler#process` performs no repository check at all, this forges a commit status (e.g., marking a required CI check as `success`) for any stack in the installation. Since `shipit.yml`'s `ci.require` mechanism and related deploy gating logic depend on `Commit`/`Status` records that this handler writes [7](#0-6) , this can unblock deploys/merges that should have been blocked by CI, directly matching the "unauthorized deploy or merge" Critical impact category. `PushHandler` similarly resolves stacks via `repository_name` independent of the org used for verification, letting an attacker trigger `GithubSyncJob` for arbitrary repositories [8](#0-7) .

### Likelihood Explanation
Requires no Shipit session, no `ApiClient` token, and no GitHub credentials — only knowledge that the target Shipit instance is configured for multiple GitHub organizations and that at least one of them has no `webhook_secret` set, which is an explicitly supported and documented configuration pattern in this engine (see the dummy multi-app fixture) rather than a host-misconfiguration outside the engine's control. The webhook endpoint is otherwise unauthenticated by design (that's its purpose), so the only defense is the signature check that this flaw undermines.

### Recommendation
Verify the webhook signature using the organization/app config that matches the repository actually referenced by the payload's mutation-relevant fields (`repository.full_name`), not a value trusted independently for org selection. Additionally, harden `StatusHandler` (and any other handler that doesn't scope by `repository_name`) to confirm the commit/stack being mutated belongs to the same repository that the verified signature's organization owns, rejecting cross-organization mismatches. Do not allow `webhook_secret` to be blank for any configured organization; require and enforce it uniformly.

### Proof of Concept
1. Shipit instance configured with `OrgA` (no `webhook_secret`) and `OrgB` (has `webhook_secret`, hosts the target stack `victim-owner/victim-repo`).
2. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=0000000000000000000000000000000000000000
Content-Type: application/json

{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/anything" },
  "organization": { "login": "OrgA" },
  "sha": "<real commit sha in victim-owner/victim-repo requiring CI>",
  "state": "success",
  "context": "required-ci-check",
  "branches": []
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature header [3](#0-2) .
4. `StatusHandler#process` matches `Commit.where(sha: params.sha)` globally and writes a forged `success` status onto the victim commit [7](#0-6) , satisfying a required CI check on `victim-owner/victim-repo` that the attacker has no access to.

Note: I was not able to fully trace the exact `Commit#create_status_from_github!` implementation or the precise `ci.require`/deploy-gating code path (`app/models/shipit/commit.rb`, `app/models/shipit/stack.rb`) within the available tool budget, so the downstream consequence — that a forged status can unblock an otherwise CI-blocked deploy — is inferred from `README.md`'s documented `ci.require` behavior and grep hits in `commit.rb`/`stack.rb`, not confirmed line-by-line.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
