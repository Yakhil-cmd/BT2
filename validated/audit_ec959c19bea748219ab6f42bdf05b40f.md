### Title
Webhook organization-authentication binding is broken from repository-target binding, allowing cross-organization event forgery in multi-tenant deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment, the webhook HMAC signature is verified using the GitHub App secret selected via `repository_owner` (`repository.owner.login` / `organization.login`), while the repository that handlers actually act on is selected via a separate field, `repository.full_name`. Because these two fields are never cross-checked, an org admin who legitimately possesses their *own* organization's `webhook_secret` can craft a signed payload whose `repository.owner.login` names their own org (so verification succeeds against their own secret) while `repository.full_name` names a repository belonging to a *different* configured organization/tenant. The engine will then process the event against that other tenant's stack.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against strictly from the payload's owner/org field: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization config/secret from `secrets.github`, supporting genuinely independent tenants each with their own `webhook_secret`: [3](#0-2) 

Once the signature check passes, the *actual* event processing resolves the target repository/stack from a **different** field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` splits `owner/name` and looks the repository up purely from this string, independent of `repository.owner.login`: [5](#0-4) 

The signature check is only bound to `repository.owner.login`/`organization.login`; nothing enforces that `repository.full_name` starts with that same owner. Since the HMAC in `verify_webhook_signature` is computed over the raw JSON body as a whole: [6](#0-5) 

...an attacker who legitimately administers **their own** tenant/org in a multi-org Shipit install (and thus knows that org's `webhook_secret`, having configured GitHub to deliver to Shipit with it) can sign an arbitrary payload body themselves. They set `repository.owner.login` (and/or `organization.login`) to their own org so `Shipit.github(organization: repository_owner)` picks their own known secret and verification succeeds, while setting `repository.full_name` to `"other-tenant-org/some-repo"`. This is a break of the equality: `organization that authenticated == repository that is written`. This is a direct GitHub-App-config analog of the H-6 report's core class of bug — a payload field (`repository.full_name`, "the repository being acted on") is not covered/bound by the same check that validates a different field (`repository.owner.login`, "the identity being authenticated"), letting one authenticated identity's credentials drive state changes scoped to an unrelated entity.

### Impact Explanation
By forging `repository.full_name` while authenticating as their own org, a tenant admin can drive `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, or `pull_request/*` handlers against another tenant's stacks/repositories that they have no legitimate access to. Most notably, `StatusHandler` creates `Status` records (commit CI status, e.g. `success`/`pending`/`failure`) for the target commit; forging a fabricated `success` status on another org's commit can satisfy `ci.require` checks and enable an **unauthorized deploy** of that commit through the victim's stack — this maps to the report's High/Critical impact bucket ("unauthorized deploy"). `PushHandler`/`GithubSyncJob` and PR handlers similarly allow injecting/altering stack state (e.g., auto-provisioning review stacks, closing/merging PR-driven review stacks) for a repository the attacker does not own, purely by controlling their own org's webhook secret.

### Likelihood Explanation
This requires the engine to be configured for **multiple** GitHub organizations sharing one Shipit instance (`secrets.github` keyed by multiple orgs, each with distinct `webhook_secret`s) — a supported, documented configuration (`TOP_LEVEL_GH_KEYS`, `github_app_config`). Any tenant admin in such a deployment already has the credential needed (their own webhook secret) and only needs to POST a manually-crafted JSON payload to the shared `/webhooks` endpoint. No GitHub App private key, `api_clients_secret`, or session is required — only knowledge of one's own legitimately-provisioned webhook secret, which is not treated as a privileged/trusted credential by the rules (it is a standard per-tenant webhook secret, not `webhook_secret` in the sense of exclusion since it's the attacker's *own*, not the app-wide secret needed to compromise others).

### Recommendation
Bind the two fields together before dispatching to handlers: after verifying the signature against the secret selected by `repository_owner`, additionally assert that `payload.dig('repository', 'full_name')` (and `organization.login`, if present) is prefixed by/equal to that same `repository_owner`, rejecting the webhook (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` exclusively via the same organization used for signature verification rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs in `secrets.github`: `org-a` (attacker-controlled, webhook secret known to attacker) and `org-b` (victim tenant, different webhook secret unknown to attacker).
2. Attacker crafts a `status` (or `push`) webhook JSON body with:
   - `organization.login` / `repository.owner.login` = `"org-a"`
   - `repository.full_name` = `"org-b/victim-repo"`
   - `sha`, `state: "success"`, target commit belonging to `org-b`'s stack.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-secret, raw_body)` themselves (since they legitimately know `org-a`'s webhook secret) and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")`, validates the signature successfully against `org-a`'s secret.
5. `StatusHandler` (via `Handler#stacks`/`#repository_name`) resolves `Repository.from_github_repo_name("org-b/victim-repo")` and creates/updates a `Status` for `org-b`'s commit as `success`, independent of `org-a`'s authorization over `org-b`'s repository.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
