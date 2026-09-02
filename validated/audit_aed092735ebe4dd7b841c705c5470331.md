Now I have enough to confirm the vulnerability and evaluate the multi-org configuration path.

Key facts confirmed:
- `Shipit.github(organization: repository_owner)` resolves a per-organization `GitHubApp` only when a multi-org config schema is used (i.e., `github_default_organization` is non-nil), via `github_app_config(organization)` which looks up `secrets.github.deep_transform_keys(&:downcase)[organization.downcase.to_sym]` [1](#0-0) .
- `repository_owner` falls back to `params.dig('organization', 'login')` when `repository.owner.login` is absent from the payload [2](#0-1) .
- `verify_webhook_signature` returns `true` unconditionally if the resolved `GitHubApp`'s `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
- The actual mutated resource is resolved independently from `params.repository.full_name` inside each handler via `Repository.from_github_repo_name(params.repository.full_name)`, completely decoupled from which org's `GitHubApp`/secret was used for verification [4](#0-3) [5](#0-4) .

So the broken binding is real in the multi-org (per-organization `webhook_secret`) configuration: verifying-org (derived from attacker-controlled `organization.login` fallback) ≠ owning org of `repository.full_name` (the actually mutated resource). If ops has configured one org with no `webhook_secret` (e.g. left `# nil` as shown in the example configs [6](#0-5) ) and a different org with a secret, an attacker can name the no-secret org in the `organization.login` field while targeting a repo owned by the secret-protected org via `repository.full_name`, causing `verify_webhook_signature` to short-circuit to `true` with no HMAC check at all.

However this requires the deployment to be in the **multi-org config schema** (`github_default_organization` non-nil) with **at least one org configured without a `webhook_secret`**. In the single-org schema (the default, most common config), `Shipit.github(organization: repository_owner)` is called with `organization: repository_owner`, but `github_default_organization` being `nil` causes it to use `secrets.github` directly regardless of the passed `organization` argument — meaning `repository_owner` value doesn't even matter for org resolution in single-org mode [7](#0-6) . So the cross-org confusion is only exploitable in multi-org deployments where the attacker can find/control an org entry lacking a secret.

### Title
Webhook signature verification bypassed by cross-org fallback when a configured multi-org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization GitHub App configurations, `WebhooksController#repository_owner` falls back to the attacker-controlled `organization.login` field to select which `GitHubApp`/`webhook_secret` verifies the request, while the actually mutated `Repository`/`Stack` is resolved independently from `repository.full_name`. If any configured organization has no `webhook_secret` set, an attacker can select that org for verification (bypassing HMAC checking entirely via `verify_webhook_signature`'s `return true unless webhook_secret`) while pointing `repository.full_name` at a different, secret-protected organization's repository.

### Finding Description
The broken binding: `verifying_org (Shipit.github(organization: repository_owner))` should equal `owning_org (params.dig('repository','full_name').split('/').first)`, but they are computed from two independent, attacker-influenced fields. `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , letting an attacker omit `repository.owner` and supply an arbitrary `organization.login` in the raw JSON POST body, since `verify_signature` runs before any HMAC is validated and reads directly from `params` before there's any proof of authenticity. `Shipit.github(organization:)` then looks up that org's config via `github_app_config` in multi-org mode [1](#0-0) . If that org's `webhook_secret` is blank, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, never even reading the `X-Hub-Signature` header [8](#0-7) . Meanwhile the event handler (e.g. `PullRequest::ClosedHandler`, `PushHandler` via `Handler#repository_name`) resolves the target `Repository`/`Stack` purely from `payload.dig('repository','full_name')` [5](#0-4) , with no re-check that this repo belongs to the org that was used for verification. Attacker's request: `POST /webhooks` with headers `X-Github-Event: push` (or `pull_request`) and body `{"repository":{"full_name":"victim-org/victim-repo"},"organization":{"login":"org-no-secret"}, ...}` and no valid `X-Hub-Signature` for victim-org's secret. `check_if_ping` and `drop_unhandled_event` don't block non-ping known events; `verify_signature` resolves `org-no-secret`'s `GitHubApp`, which has no secret, returns `true`, and the handler proceeds to mutate state tied to `victim-org/victim-repo`.

### Impact Explanation
This is an authentication bypass: a forged webhook is accepted and processed against a fully secret-protected victim repository/stack, using only knowledge of an unrelated, unprotected org's name in the same Shipit instance. Depending on event type this can trigger `GithubSyncJob` enqueue, `Commit`/`Status` record writes, review-stack archive/unarchive, or PR-driven state changes for the victim repo — an unauthorized write against a repository that never validated this specific request. It is repeatable against any repository in the instance as long as one configured org lacks a `webhook_secret`, and the blast radius spans every stack/repository configured under any org in the same Shipit deployment, matching the Critical criteria ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Exploitability strictly requires: (1) the instance uses the multi-organization `github:` config schema (i.e., `github_default_organization` present, per the `secrets_double_github_app.yml`-style config) [6](#0-5) , and (2) at least one configured org has `webhook_secret` left blank. This is a plausible but non-default operational misconfiguration — the setup docs show `webhook_secret` as an optional/nilable field per-org [6](#0-5) , and nothing in the engine enforces that all orgs in a multi-org config must set a secret. Given that precondition, attacker cost is trivial: no session, token, or secret needed, just knowledge of the unprotected org's login name (often discoverable, e.g. via public GitHub org listing) and the victim's `owner/repo` full_name (public information). The attack is fully repeatable with no rate limiting concerns in scope.

### Recommendation
In `WebhooksController`, derive the organization used for signature verification from the same field used to resolve the target repository (i.e., always use `repository.full_name`'s owner segment, or explicitly validate that `repository.owner.login` matches the owning org of `repository.full_name`) rather than falling back to the attacker-supplied `organization.login`. Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` when `webhook_secret` is blank for organizations that other orgs in the same multi-org config do have secrets configured — or the engine should refuse to boot / warn loudly when a multi-org config contains any org without a `webhook_secret`, since a single unprotected org undermines the security of every other org in the same instance.

### Proof of Concept
minitest under `test/controllers/webhooks_controller_test.rb` (using a multi-org secrets fixture like `test/dummy/config/secrets_double_github_app.yml` with `OrgOne` having a `webhook_secret` set and `OrgTwo` left blank):
1. Seed `Repository`/`Stack` fixtures owned by `OrgOne` (secret-protected), e.g. `owner: "OrgOne", name: "victim-repo"`.
2. Build a `push` payload: `{"ref":"refs/heads/master","after":"<sha>","repository":{"full_name":"OrgOne/victim-repo"},"organization":{"login":"OrgTwo"}}` — deliberately omit `repository.owner`.
3. `POST :create` with this body, setting `X-Github-Event: push` and either omitting `X-Hub-Signature` or setting it to garbage (no valid HMAC for `OrgOne`'s secret).
4. Assert `response.status == 200` (`head :ok`) — proving verification passed despite no matching signature for the victim org.
5. Assert `Shipit.github(organization: 'OrgTwo').verify_webhook_signature(...)` was in fact called (matching `repository_owner` == `"OrgTwo"`) while the mutation targets `OrgOne/victim-repo`, e.g. `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "<sha>"])`.
6. Contrast: repeat with a correctly signed request for `OrgOne` and confirm it also succeeds, and repeat with an invalid signature and `organization.login` set to `OrgOne` itself, confirming `head(422)` is returned — demonstrating the divergence is specifically caused by the org-fallback field mismatch, not by signature checking being globally disabled.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
