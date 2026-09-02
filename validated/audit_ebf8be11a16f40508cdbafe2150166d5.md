### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field, enabling cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), while the actual webhook handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc., via `Shipit::Webhooks::Handlers::Handler#repository_name`) resolve the target `Repository`/`Stack` using the independent `repository.full_name` field from the very same untrusted JSON body. Nothing ties these two fields together, so the field that is cryptographically authenticated is not the field that is acted upon — the exact class of "field acted on but never covered by the effective check" binding break called out in the source report.

### Finding Description
`verify_signature` in [1](#0-0)  computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is read straight out of the attacker-suppliable JSON body: [2](#0-1) .

`Shipit.github(organization:)` looks up a *per-organization* `webhook_secret` from `secrets.github` in multi-tenant configurations, exactly as documented for `Using Multiple Github Applications`, where each organization key has its own `webhook_secret` [3](#0-2) , and is implemented in `Shipit.github`/`github_app_config` [4](#0-3) .

`GitHubApp#verify_webhook_signature` only checks that the HMAC over the full raw body matches the secret belonging to the organization named in the payload — it never checks that this organization is the one whose repository is actually referenced elsewhere in the payload: [5](#0-4) .

Once verification passes, `WebhooksController#create` dispatches the full parsed body to matching handlers unchanged: [6](#0-5) .

Every handler, however, resolves its target stacks/commits from a *different* field, `repository.full_name`, via the shared base class: [7](#0-6) . For example `PushHandler#process` triggers `stack.sync_github` for whichever stacks match that `full_name` [8](#0-7) , and `StatusHandler#process` creates commit statuses for commits matched purely by `sha`, with no organization/owner check at all [9](#0-8) .

Equality that should hold but does not: `organization used to select verify_webhook_signature's secret == owner of repository.full_name acted on by the handler`. Because both `repository.owner.login`/`organization.login` and `repository.full_name` are independently attacker-controlled fields inside the same unauthenticated JSON body (the controller only authenticates the byte string as a whole against a secret chosen by one of those fields), an attacker who legitimately knows the `webhook_secret` for *any one* organization configured in a multi-tenant Shipit instance (e.g. their own organization, onboarded through the documented multi-org flow) can forge a signed payload where `repository.owner.login`/`organization.login` names their own org (so their known secret validates), while `repository.full_name` names a repository belonging to a completely different, victim organization tracked by the same Shipit install. The signature check passes, and the handler acts on the victim's stack.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out as in-scope. Concrete cross-organization writes achievable this way:
- `push` events: forge `PushHandler` to trigger `stack.sync_github(expected_head_sha:)` against a victim stack, forcing a resync to an attacker-chosen SHA/branch state.
- `status` events: forge arbitrary CI status (`success`/`failure`) via `StatusHandler#process` → `commit.create_status_from_github!`, directly manipulating the CI-gate signal that Shipit's deploy safety checks rely on for a victim's commit, since matching is done purely by `sha` with no owner scoping.
- `check_suite` events: force `CheckSuiteHandler` to schedule check-run refreshes on victim commits.

This constitutes an unauthorized cross-repository write into stacks/commits the attacker does not own, satisfying the "cross-repository writes" Critical impact category, achievable purely by knowing one legitimately-issued, lower-trust organization's webhook secret in a multi-org deployment.

### Likelihood Explanation
Requires only: (1) a multi-organization Shipit deployment (a documented, supported configuration), and (2) the attacker knowing the `webhook_secret` for at least one organization onboarded into that Shipit instance — a low-trust bar in installations where multiple, independently-administered organizations are configured, since each org owner independently generates and supplies their own `webhook_secret` value at setup time and could weaponize their own known secret. No GitHub App private key, session, or `ApiClient` token is required — only an HTTP POST to the public `/webhooks` endpoint with a crafted, self-signed body. This is unauthenticated w.r.t. the victim organization, matching the required attacker model.

### Recommendation
After parsing the payload, verify that `repository.owner.login` (or `organization.login`) used to select the signing secret matches the owner segment of `repository.full_name` before dispatching to handlers; reject the webhook (422) on mismatch. Alternatively, have handlers resolve the target repository using the same owner field that was cryptographically verified, rather than trusting `full_name` independently.

### Proof of Concept
1. Attacker is (or controls) organization `attacker-org`, which is configured in a multi-org Shipit `secrets.yml` with its own known `webhook_secret = "atk-secret"`.
2. Victim organization `victim-org` is configured separately with a `webhook_secret` unknown to the attacker, and owns a repository `victim-org/victim-repo` tracked as a Shipit stack.
3. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, "atk-secret")>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` reads `repository_owner` as `"attacker-org"`, fetches `attacker-org`'s app/secret, and the HMAC matches → verification succeeds [10](#0-9) .
6. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's real commit sha — and calls `create_status_from_github!`, injecting a forged `success` status onto the victim's commit, with no relation to `attacker-org` ever checked [9](#0-8) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
