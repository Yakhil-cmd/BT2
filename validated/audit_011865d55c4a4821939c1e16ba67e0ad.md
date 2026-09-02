## Analog Vulnerability Found

This confirms multi-org support: `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key found in `secrets.github` [1](#0-0) , and `GitHubApp#verify_webhook_signature` explicitly **skips verification entirely when that organization's `webhook_secret` is blank**: `return true unless webhook_secret` [2](#0-1) .

### Title
Webhook organization used for signature verification is not bound to the repository the event payload acts on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) is used to authenticate an inbound webhook based on `params.dig('repository', 'owner', 'login')` [3](#0-2) [4](#0-3) . However, the event handlers that actually act on the payload resolve the target `Stack` using a completely different field: `payload.dig('repository', 'full_name')` [5](#0-4) . Nothing binds these two fields together — they are independent leaves of the same attacker-controlled JSON body.

### Finding Description
This is the direct structural analog of the audit finding: a value that gates a security decision (which organization's secret authenticates the request) is disconnected from the value that determines what the trusted action actually operates on (which repository/stack is mutated). In the original bug, the stop-loss threshold (`ADAPTER_BREAKS_LOSS_POINT`) that gated fund movement decisions was too loosely/incorrectly bound to the volatility of the actual asset, breaking the intended safety invariant. Here, the invariant "the org whose secret validated this request == the org whose repository is acted upon" is never enforced by code, only assumed to hold because in a legitimate GitHub webhook `repository.owner.login` is a prefix of `repository.full_name`. Nothing stops a forged payload from decoupling them.

Combined with `verify_webhook_signature`'s `return true unless webhook_secret` short-circuit [6](#0-5) , if *any* configured organization in `secrets.github` (multi-org schema, keyed by org name, see `github_app_config`/`github_organizations`) [7](#0-6)  has no `webhook_secret` set, an attacker can:
1. Set `repository.owner.login` to that unsecured organization's name — signature verification for the request is bypassed unconditionally.
2. Set `repository.full_name` to `"<other-org>/<other-repo>"` — the actual repository/stack the handler mutates.

### Impact Explanation
This breaks the deployment-trust binding "organization authenticated == repository written," letting an unprivileged external caller forge push/status/check_suite/pull_request events against a Stack belonging to an organization it was never authenticated for. Handlers like the push handler enqueue `GithubSyncJob` [8](#0-7)  and pull-request handlers close/merge/label PRs based solely on `payload` content resolved via `repository_name` [9](#0-8) , without ever re-checking that the authenticated organization matches the target stack's actual owning repository. This is a cross-repository/cross-organization write via a forged, effectively-unsigned webhook — satisfying the "cross-repository writes" Critical-impact bar, contingent on the exploitability condition below.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it only manifests when an operator runs the multi-organization `secrets.github` schema (keyed by org) and at least one configured organization entry omits `webhook_secret`, or when `repository_owner` fails to resolve strictly to a known org and hits the "backward compatibility" single-app path (`github_default_organization.nil?` → `config = secrets.github` directly) [10](#0-9) , whose top-level `webhook_secret` could also be unset per the documented setup (`webhook_secret: some-secret-value` is optional/nullable in `docs/setup.md` and defaults to `nil` in test secrets) [11](#0-10) . This is a configuration-dependent, not universally-reachable, bypass — I could not verify from the indexed code whether the production/reference deployment enforces `webhook_secret` presence for every configured org, so likelihood should be treated as conditional rather than confirmed.

### Recommendation
1. In `GitHubApp#verify_webhook_signature`, do not silently pass verification when `webhook_secret` is blank; instead treat a missing `webhook_secret` for a configured organization as a hard misconfiguration (raise/log and reject) rather than an implicit bypass. [2](#0-1) 
2. In `Handler#repository_name` / `WebhooksController#repository_owner`, explicitly assert that the repository resolved for stack lookup belongs to the same organization that was used to select the signing secret (e.g., compare `payload.dig('repository', 'owner', 'login')` against the owner segment of `payload.dig('repository', 'full_name')`) and reject on mismatch. [9](#0-8) [4](#0-3) 

### Proof of Concept
Preconditions: Shipit configured with multi-org `secrets.github` schema; organization `unsecured-org` present in config with `webhook_secret` unset/nil; organization `victim-org` is a real configured tenant with a `Stack`.

1. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or an arbitrary one).
2. JSON body:
```json
{
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/production-repo"
  },
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` calls `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) signature header. [6](#0-5) [3](#0-2) 
4. `Shipit::Webhooks.for_event('push')` handler runs and resolves the target repository/stack via `payload.dig('repository', 'full_name')` = `"victim-org/production-repo"`, enqueuing `GithubSyncJob` against `victim-org`'s stack — despite the request never being authenticated for `victim-org`. [5](#0-4) 

Note: I could not confirm within the indexed engine code whether any shipped default configuration or documented setup path actually leaves `webhook_secret` unset for a real multi-tenant deployment — this determines whether the bypass is reachable in practice versus only under misconfiguration. If you need to check actual production secrets files or additional handler code beyond what the index returned, a full-repository session would be required.

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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```

**File:** test/dummy/config/secrets.yml (L8-13)
```yaml
  github:
    domain: # defaults to github.com
    app_id: 42
    installation_id: 43
    bot_login: "shipit[bot]"
    webhook_secret: # nil
```
