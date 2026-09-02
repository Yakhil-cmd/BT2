This confirms the mechanism. When Shipit is configured for multi-organization GitHub Apps (`Shipit.github_organizations`), `Shipit.github(organization:)` looks up per-org config via `github_app_config` [1](#0-0) , and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org's `webhook_secret` is blank/unset [2](#0-1) . The `organization` used to select this config comes straight from the unauthenticated webhook payload's `repository.owner.login` (or `organization.login`) [3](#0-2) , while the actual data the handlers act on (which `Stack`/`Repository` gets synced, which commit gets a status, which check run gets refreshed) is read from a **different** field, `repository.full_name`, in `Handler#repository_name` and `Handler#stacks` [4](#0-3) . Nothing ties these two fields together.

### Title
Webhook signature verification is keyed off an attacker-chosen organization field that is never cross-checked against the repository the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate a webhook against using `repository_owner`, a value taken directly from the untrusted JSON body (`repository.owner.login` or `organization.login`). Handlers downstream (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, all inheriting from `Handler`) instead resolve the target `Stack`/`Repository` using a *different* field in the same untrusted body: `repository.full_name`. The two fields are never checked for consistency with each other or against the record they are supposed to represent.

### Finding Description
`GithubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) short-circuits to `true` whenever `webhook_secret` is blank for the selected organization config — this is explicitly a supported/documented configuration (`docs/setup.md` and `test/dummy/config/secrets.yml` both show `webhook_secret: # nil` as valid). In a multi-organization deployment (`Shipit.github_organizations`, `Shipit.github_app_config`, `lib/shipit.rb:190-200`), each org can have its own `webhook_secret`; some orgs may legitimately have none configured (e.g. during onboarding, or Enterprise setups that never received a secret).

`WebhooksController#verify_signature` determines *which* org's config/secret to check against purely from `repository_owner`, itself parsed from the POST body:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
This is the equality the deployment implicitly relies on: *the organization whose secret authenticates the request* must equal *the organization/repository the handlers subsequently write to*. But the handlers (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`) resolve their target purely from `repository.full_name`:
```
def repository_name
  payload.dig('repository', 'full_name')
end
```
Because the signature check and the target-resolution logic read *different, independently-controlled fields* from the same attacker-supplied JSON body, an attacker can set `repository.owner.login` to any organization that has no `webhook_secret` configured (bypassing HMAC verification entirely, since `verify_webhook_signature` returns `true` unconditionally in that case) while setting `repository.full_name` to any repository/stack actually tracked by Shipit, including ones belonging to entirely different, secret-protected organizations.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written." An unauthenticated attacker who knows only that some org in a multi-org Shipit deployment has no webhook secret configured can forge arbitrary `push`, `status`, and `check_suite` events for any *other* tracked repository/stack:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for the target stack, forcing an out-of-band GitHub sync and, on stacks with `continuous_deployment` enabled, can drive an unauthorized deploy pipeline trigger.
- `StatusHandler` injects fabricated commit statuses (`commit.create_status_from_github!`), which can be used to satisfy `ci.require` checks and unblock deploys that should be gated on real CI results.
- `CheckSuiteHandler` can trigger `schedule_refresh_check_runs!` against arbitrary commits.

Combined with CI-status spoofing, this can enable an unauthorized deploy of a stack the attacker has no legitimate relationship to, meeting the "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires only: (1) the webhooks endpoint being reachable (it is, unauthenticated, mounted at the engine's `/github/webhooks`-style route and inherits no `Authentication` concern — see `app/controllers/shipit/webhooks_controller.rb:1-6`), and (2) a multi-org Shipit deployment where at least one configured organization has no `webhook_secret` set — a state the project's own docs and default `secrets.yml`/`setup.md` examples show as valid. No credentials, tokens, or repository write access are needed by the attacker; they only need to know that such an organization exists (or brute force `repository_owner` values, since 404 vs 422 responses reveal which organizations are "known").

### Recommendation
Do not let `repository_owner` (attacker-controlled) alone decide the trust boundary for otherwise-unauthenticated payloads. Cross-validate that the resolved `Repository`'s stored owner matches `repository.full_name`'s owner segment, and reject any org config with a blank `webhook_secret` from bypassing verification (require an explicit, opt-in flag instead of "absence of secret == success"). At minimum, ensure `repository_name` used by `Handler` is derived from the same, already-verified `repository_owner`, not re-read independently from the payload.

### Proof of Concept
1. Configure Shipit with multi-org GitHub Apps: `orgA` (has a `webhook_secret`) tracking `orgA/private-repo`, and `orgB` (no `webhook_secret` configured, e.g. left blank during onboarding).
2. POST to the webhooks endpoint with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgB" },
    "full_name": "orgA/private-repo"
  }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `Shipit.github(organization: "orgB")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`).
4. `PushHandler#process` resolves `stacks` via `repository.full_name` = `"orgA/private-repo"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` for the `orgA` stack — a forged, unauthenticated GitHub event for a repository protected by a real secret. [3](#0-2) [2](#0-1) [4](#0-3) [5](#0-4)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
