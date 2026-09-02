## Title
Webhook signature verification is keyed on an unauthenticated field, allowing forged push/webhook events to target repositories outside the verified organization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted, unsigned-at-that-point request body [1](#0-0) [2](#0-1) . The actual work performed by the handler (e.g. `PushHandler`) resolves the target `Repository`/`Stack` from a *different* payload field, `repository.full_name` [3](#0-2) [4](#0-3) . Because `GithubApp#verify_webhook_signature` unconditionally returns `true` when the resolved app config has no `webhook_secret` configured [5](#0-4) , and `webhook_secret` is documented/shipped as optional per organization [6](#0-5) , an attacker can pick an organization key that has no secret configured, put that organization's login in `repository.owner.login` (which only affects which config is selected for verification), and put an arbitrary *other* organization/repository's full name in `repository.full_name` (which is what actually gets acted on). Verification passes trivially (no secret to check against), yet the handler performs a real, unauthenticated write (queuing a `GithubSyncJob`, creating Users/Teams/Memberships for `membership` events, etc.) against a repository that was never covered by any valid signature.

### Finding Description
The binding that should hold is:
`organization whose signature was verified == organization/repository the handler writes to`

In this engine that binding is broken because two different, independently-attacker-controlled JSON fields are used for two different purposes:
- `repository_owner` (from `params.dig('repository','owner','login')` or `organization.login`) selects the `GithubApp` instance and its `webhook_secret` used for HMAC verification [7](#0-6) [2](#0-1) .
- `repository.full_name` is what the handlers actually use to look up the `Repository`/`Stack` and perform side effects [3](#0-2) .

Nothing forces these two fields to reference the same organization. Combined with `verify_webhook_signature` treating a missing/blank `webhook_secret` as automatically verified [5](#0-4) , in any multi-org deployment where at least one configured organization omits `webhook_secret` (shown as an accepted, commented "# nil" configuration in the shipped example secrets files [8](#0-7) [6](#0-5) ), an unauthenticated attacker can:
1. Set `repository.owner.login` (or `organization.login`) to the org with no `webhook_secret`.
2. Set `repository.full_name` (and other event fields) to reference a repository belonging to a *different*, properly-secured organization/stack.
3. Send the crafted POST to `/webhooks` with any/no `X-Hub-Signature`.

`verify_signature` resolves `Shipit.github(organization: 'org-with-no-secret')`, calls `verify_webhook_signature`, which returns `true` because `webhook_secret` is blank — regardless of the signature header or the (mismatched) target repository named elsewhere in the payload [1](#0-0) . The request then proceeds to `create`, which dispatches to the registered handler for the event and executes real side effects against the stack matched from `repository.full_name` [9](#0-8) [4](#0-3) .

This is the direct analog of the reported bug class: a field the application acts on (`repository.full_name`, driving which stack gets synced/mutated) is never itself covered by any binding to the verified signature/secret — the verification instead binds to an unrelated field (`repository.owner.login`) that an attacker fully controls.

### Impact Explanation
This allows an unauthenticated attacker to trigger `GithubSyncJob` for arbitrary stacks (forged `push` events causing Shipit to sync commit/deploy state from GitHub using cached, potentially stale credentials) [4](#0-3) , and to trigger `membership` handler side effects that create `Team`/`User`/`Membership` records, which is directly relevant because `Shipit.github_teams` membership drives authorization (`current_user.authorized?`) in the authentication layer [10](#0-9) . Forged `membership` webhooks that add an attacker-controlled user to a privileged team could escalate into `Shipit.github_teams` authorization — matching the "High" impact category (escalation into `Shipit.github_teams` authorization / unauthenticated write of stack state).

### Likelihood Explanation
Requires only that the deployment is configured with multiple GitHub organizations where at least one has no `webhook_secret` set — a configuration explicitly presented as valid/optional in the shipped example secrets files [8](#0-7) [6](#0-5) . No credentials, tokens, or prior access are needed — only knowledge of the organization name lacking a secret and the target repository's `full_name`, both of which are typically public information.

### Recommendation
Bind signature verification to the same identity that is acted upon: verify the signature using the `GithubApp` config resolved from `repository.full_name`'s owner (or require them to match `repository_owner` before dispatch), and stop treating an absent `webhook_secret` as automatically-verified — instead reject (422) when no secret is configured for an organization, or require every configured organization to set a webhook secret.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `org-a` (no `webhook_secret`) and `org-b` (has a real stack, e.g. `org-b/secure-repo`, tracked by Shipit).
2. POST to `/webhooks` with:
   - Header `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "org-a"}, "full_name": "org-b/secure-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha>"}`
   - No valid `X-Hub-Signature` header (or any garbage value).
3. `verify_signature` resolves `Shipit.github(organization: 'org-a')`; since `org-a` has no `webhook_secret`, `verify_webhook_signature` returns `true` per [11](#0-10) .
4. `create` dispatches to `PushHandler`, which resolves the repository via `repository.full_name` = `org-b/secure-repo` [3](#0-2)  and enqueues `GithubSyncJob` for that stack with attacker-chosen `expected_head_sha` [4](#0-3)  — despite `org-b`'s webhook never being signed by the real GitHub App.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
