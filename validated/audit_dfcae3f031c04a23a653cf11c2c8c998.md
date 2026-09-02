### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` but handlers act on the unrelated `repository.full_name` field, letting a webhook signed for one (secret-less) org write CI status onto commits of any other tracked stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a payload against using `repository_owner` (`repository.owner.login`, falling back to `organization.login`) [1](#0-0) [2](#0-1) . Every event handler, however, resolves the target `Stack`/`Repository` it acts on from a **different** payload field, `repository.full_name`, via `Handler#stacks`/`Handler#repository_name` [3](#0-2) . These two fields are never checked for consistency.

Compounding this, `GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the selected organization: `return true unless webhook_secret` [4](#0-3) . Shipit's own documented multi-org config format explicitly allows `webhook_secret` to be left blank/`nil` per organization [5](#0-4) , and `Shipit.github_app_config` resolves whichever organization name the request itself names [6](#0-5) .

### Finding Description
The binding that should hold is: *the organization whose secret authenticated the webhook = the repository the handler writes to*. It does not.

1. `verify_signature` computes `repository_owner` from the attacker-supplied JSON body itself (`params.dig('repository','owner','login') || params.dig('organization','login')`), then calls `Shipit.github(organization: repository_owner)` to obtain the `GitHubApp` instance used to verify the HMAC signature [1](#0-0) .
2. If that organization's config has no `webhook_secret` set (a state the shipped example config explicitly documents as valid: `webhook_secret: # nil`), `verify_webhook_signature` returns `true` regardless of the actual `X-Hub-Signature` header or payload content [4](#0-3) . No credential is required at all to pass verification for such an organization.
3. Once verification passes, `WebhooksController#create` dispatches the *entire raw payload* to every registered handler for the event type [7](#0-6) .
4. Handlers never re-check `repository.owner.login`; they look up the target repository/stack using `repository.full_name` instead: `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')` [3](#0-2) .
5. `StatusHandler` is the most impactful example: it takes attacker-controlled `sha`, `state`, `description`, `target_url`, `context` from the payload and writes a `Status` onto any `Commit` matching that `sha` anywhere in the Shipit instance - it never checks which org/repo owns that commit at all [8](#0-7) . `PushHandler` similarly resolves `stacks` purely from `repository.full_name` and triggers `stack.sync_github` [9](#0-8) .

Net effect: in a multi-organization Shipit deployment (the config format Shipit ships and documents supports many orgs under one instance, see `github_organizations`/`github_app_config` in `lib/shipit.rb`), an attacker who can make the "authenticating" organization field name any org whose `webhook_secret` happens to be unset bypasses all cryptographic verification, then freely names `repository.full_name` of a totally unrelated, secret-protected stack to inject fabricated commit statuses (or trigger syncs) against it - i.e., the org that "authenticated" the request is not the repository actually written.

### Impact Explanation
Writing a fabricated `success` `Status` for an arbitrary commit sha on a protected production stack directly undermines `ci.require`/`ci.blocking` gating in `DeploySpec` (`required_statuses`, `blocking_statuses`) [10](#0-9) , which Shipit's deploy/merge-queue logic uses to decide whether a commit is deployable/mergeable. Forcing a fake passing CI status on a commit that never actually passed CI can enable an unauthorized deploy or an unauthorized merge-queue advancement, which matches the Critical-tier impact ("an unauthorized deploy, rollback or merge"). This is possible without possessing any `ApiClient` token, `webhook_secret`, `api_clients_secret`, or GitHub App private key, and without any Shipit session - contingent on the deployment having at least one configured GitHub org without a `webhook_secret` (a configuration state the project's own template explicitly shows as acceptable).

### Likelihood Explanation
Exploitability depends entirely on deployment configuration: a single-organization Shipit instance with a properly set `webhook_secret` is not exploitable this way, since `Shipit.github(organization: repository_owner)` will resolve to the one org whose real secret is required. The finding applies specifically to multi-org deployments where at least one configured org lacks a `webhook_secret` — a state the engine's shipped example config format treats as a supported, non-error configuration rather than rejecting it. I could not verify from static analysis whether any real-world Shipit deployment actually runs with a nil `webhook_secret` for one of several configured orgs; that is a deployment-level fact outside the scope of this codebase.

### Recommendation
- In `WebhooksController#verify_signature`/handlers, bind the *same* field used for organization/authentication selection to the field used for repository resolution — e.g., derive `repository_name` for handler dispatch strictly from the already-authenticated `repository_owner` context, or explicitly assert `repository.owner.login == organization used to authenticate` before dispatch.
- Treat an unset/`nil` `webhook_secret` as a configuration error (raise, refuse to boot, or force `verified = false`) rather than as "skip verification" in `GithubApp#verify_webhook_signature`.
- Have `Handler#stacks`/`StatusHandler` etc. scope commit/repository lookups to the repository namespace implied by the authenticated organization, not to attacker-controlled `full_name` alone.

### Proof of Concept
Conceptual (network-only, no credentials), assuming a Shipit instance configured with orgs `no-secret-org` (no `webhook_secret`) and `victim-org/victim-repo` (a real, secret-protected tracked stack):

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-empty

{
  "sha": "<victim-repo's real HEAD sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```

- `verify_signature` resolves `repository_owner` = `"no-secret-org"`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally [4](#0-3) [1](#0-0) .
- `StatusHandler#process` then finds `Commit.where(sha: params.sha)` across the whole instance (not scoped to `no-secret-org`) and creates a `success` status on it [8](#0-7) , satisfying `victim-org/victim-repo`'s required CI checks without ever touching that org's real (secret-protected) webhook secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
