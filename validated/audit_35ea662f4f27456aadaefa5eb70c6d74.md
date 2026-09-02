### Title
Organization selected for webhook-signature verification can differ from the repository the webhook payload actually mutates, allowing signature-check bypass in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App config (and thus which `webhook_secret`) to verify the payload against based on an attacker-controlled field of the unauthenticated payload itself (`repository.owner.login` / `organization.login`), while the actual mutation performed by `create` operates on the (independently re-parsed) `repository.full_name` in the same payload. In a multi-organization Shipit deployment, an org whose `webhook_secret` is left blank causes `GitHubApp#verify_webhook_signature` to short-circuit to `true` unconditionally, regardless of the actual repository being targeted.

### Finding Description
`verify_signature` resolves the app/secret to check the signature against using an organization name taken straight from the untrusted payload: [1](#0-0) [2](#0-1) 

```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
head(422) unless verified
```

`Shipit.github` looks up the per-organization config by that same attacker-supplied key when the deployment uses the multi-org config schema: [3](#0-2) 

`GitHubApp#verify_webhook_signature` treats a *blank* `webhook_secret` as "verification not required" and returns `true` unconditionally: [4](#0-3) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

The equality that is supposed to hold is:
`organization whose secret authenticated the request == organization owning the repository that gets written to by create`.

After the `before_action` passes (because the *attacker-chosen* organization's config has no `webhook_secret`), `create` re-parses the same raw body and dispatches handlers keyed off `repository.full_name`/`repository.owner.login` again: [5](#0-4) [2](#0-1) 

Nothing forces the repository/organization used to pick the verification secret to be the same repository the handlers (`GithubSyncJob`, status/check-suite/merge/deploy handlers, etc.) subsequently act on — the payload is a single untrusted JSON blob, and both fields are read straight out of it without cross-checking against the stack actually stored for that repo.

### Impact Explanation
In any Shipit instance configured with the multi-organization GitHub App schema (`secrets.github` keyed by org, as demonstrated by `test/dummy/config/secrets_double_github_app.yml`), if any one of the configured organizations has no `webhook_secret` set, an unauthenticated attacker can:
1. Craft a JSON webhook body whose `repository.owner.login` is that unsecured organization (to make `verify_webhook_signature` return `true` unconditionally), while
2. Setting `repository.full_name` / commit SHAs / branch fields to point at a stack belonging to a *different*, secured organization tracked by the same Shipit instance.

This forges `push`, `status`, `check_suite`, `deployable_status`, `merge_status`, `pull_request`, or `membership` events for repositories the attacker has no legitimate access to, causing unauthorized `GithubSyncJob` enqueues, spoofed commit statuses/check-run refreshes, and forged team/user membership changes — i.e. unauthenticated read/write of stack state and an unauthorized deploy-adjacent action, matching the High-severity "escalation into `Shipit.github_teams` authorization" / "unauthenticated ... task streams" category.

### Likelihood Explanation
Requires: (a) the host to use the multi-org GitHub App configuration schema, and (b) at least one configured organization to have an unset `webhook_secret`. Both are realistic misconfigurations rather than exotic setups — the multi-org schema is a first-class, documented feature (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), and `webhook_secret` is treated as optional by the code (`.presence` fallback to `nil`, with an explicit "verification not required" branch), so nothing in the engine enforces that every org in a multi-org deployment sets one.

### Recommendation
- Do not let the *payload's* claimed organization/repository decide which secret is used to verify that same payload. Instead, either verify with all configured organizations' secrets and require a match, or verify first against a byte-for-byte signature bound to the specific stack/repository already known to Shipit (looked up independently of payload fields) before dispatching handlers.
- Remove the "no secret configured ⇒ verification always passes" short-circuit in `GitHubApp#verify_webhook_signature`, or require `webhook_secret` presence for every organization in multi-org mode at boot time.
- After signature verification, assert that the organization used for verification matches the `repository.owner.login`/`full_name` actually acted upon in `create`.

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.github`: `secure-org` (has `webhook_secret: s3cr3t`) and `open-org` (no `webhook_secret` key).
2. `secure-org/target-repo` is a tracked Shipit stack.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, and body:
```json
{
  "repository": {"owner": {"login": "open-org"}, "full_name": "secure-org/target-repo"},
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
4. `verify_signature` calls `Shipit.github(organization: "open-org")`, whose config lacks `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally regardless of the actually-missing/invalid signature.
5. `create` re-parses the same body and dispatches the `push` handler against `secure-org/target-repo`, enqueuing `GithubSyncJob` for that stack — despite the request never having been validated against `secure-org`'s secret.

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
