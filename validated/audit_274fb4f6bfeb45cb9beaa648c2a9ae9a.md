### Title
Webhook signature verification is keyed on an unauthenticated payload field while the effective repository/stack is chosen by a different, unauthenticated payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) used to authenticate an inbound webhook based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), a field taken straight from the unverified JSON body. All webhook handlers, however, resolve the `Repository`/`Stack` to act on using a *different* payload field, `payload.dig('repository', 'full_name')`. Because these two fields are never cross-checked against each other, and because signature verification is a no-op whenever the selected organization's `webhook_secret` is blank/unset (`GitHubApp#verify_webhook_signature` returns `true` if `webhook_secret` is absent), an attacker can pick an "authenticating organization" that has no (or a known) webhook secret while pointing `repository.full_name` at a stack belonging to an entirely different, protected organization.

### Finding Description
`verify_signature` in [1](#0-0)  computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is [2](#0-1) , purely payload-derived and not itself protected by any signature at the time it is read.

`Shipit.github(organization:)` looks up per-organization app configs from `secrets.github` (multi-tenant setup documented in `docs/setup.md` and exercised by `test/dummy/config/secrets_double_github_app.yml`) [3](#0-2) . Each organization can have its own, independently configured `webhook_secret`, and `GitHubApp#verify_webhook_signature` explicitly treats an absent secret as "always verified":
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 

Meanwhile, every event handler determines which `Repository`/`Stack` is affected using a completely separate field — `payload.dig('repository', 'full_name')` — via `Handler#repository_name` / `#stacks` [5](#0-4) , and `PushHandler#process` acts on any not-archived stack in that repo matching `branch` derived from `params.ref`, calling `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) .

This breaks the equality that should hold: **organization that authenticated the webhook == organization that owns the repository being written to.** The `X-Hub-Signature` only proves the request came from *some* configured organization's GitHub App (identified by `repository.owner.login`), never that this organization is the one that owns `repository.full_name`, which is what actually drives the sync/deploy logic.

### Impact Explanation
In a multi-organization Shipit deployment (the documented "Using Multiple Github Applications" configuration), if any one configured organization has no `webhook_secret` set (shown as the default/example value `webhook_secret: # nil` in `config/secrets.development.example.yml` and `secrets_double_github_app.yml`) or a secret the attacker can obtain, an attacker can forge a `push` (or `status`, `check_suite`, `pull_request`, etc.) webhook where:
- `repository.owner.login` = the organization with no/known secret (so `verify_signature` passes trivially), and
- `repository.full_name` = `victim-org/victim-repo` (a stack belonging to a different, properly-secured organization).

The forged `push` event will cause `GithubSyncJob` to be enqueued for the victim stack with an attacker-chosen `after` SHA, i.e. `stack.sync_github(expected_head_sha: params.after)`. Depending on downstream sync/merge logic this allows spoofing of commit sync state, CI/commit statuses, and check-suite results for a repository the attacker never authenticated for, which can be leveraged toward an unauthorized deploy or merge decision. This satisfies the "High" bar (unauthenticated influence over stack/task state) and, depending on how far sync state can be manipulated to trigger auto-deploy, potentially the "Critical" unauthorized-deploy bar.

### Likelihood Explanation
Requires the deploying organization to run Shipit in the documented multi-org configuration and for at least one configured organization to have a blank/guessable `webhook_secret` — a realistic and even encouraged default in the example configs shipped in this repo (`webhook_secret: # nil`). No privileged credentials, session, or `ApiClient` token are needed; the attacker only needs to be able to POST to the public `/github/webhooks` endpoint, which is unauthenticated by design (it's the GitHub webhook receiver).

### Recommendation
Verify webhook signatures using the same field that is subsequently used to resolve the affected repository/stack (`repository.full_name`'s owner), not a separately-read field. At minimum, after selecting `github_app` by `repository_owner`, re-validate that `repository.full_name`'s owner segment matches `repository_owner` before dispatching to handlers, and reject (422) on mismatch. Additionally, do not treat a missing `webhook_secret` as automatically verified in multi-organization configurations — require every configured organization to have a non-blank secret, or fail closed.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `org-empty` (no `webhook_secret` configured) and `org-victim` (properly configured, hosts the target stack `org-victim/app`).
2. POST to `/github/webhooks` with:
   - `X-Github-Event: push`
   - Body: `{"ref": "refs/heads/main", "after": "<attacker-chosen-sha>", "repository": {"owner": {"login": "org-empty"}, "full_name": "org-victim/app"}}`
   - Any `X-Hub-Signature` value (irrelevant, since `org-empty` has no secret).
3. `verify_signature` calls `Shipit.github(organization: 'org-empty').verify_webhook_signature(...)`, which returns `true` unconditionally because `webhook_secret` is blank for `org-empty` [7](#0-6) .
4. `PushHandler` resolves stacks via `repository.full_name` = `org-victim/app` [8](#0-7)  and calls `stack.sync_github(expected_head_sha: <attacker-chosen-sha>)` for the victim organization's stack, despite the request never being signed by `org-victim`'s webhook secret.

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
