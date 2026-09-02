Based on my investigation, this confirms the multi-organization webhook trust model. Here is the analysis.

### Title
Cross-organization webhook authentication bypass via mismatched signature-selection and repository-action fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App/organization secret to verify a webhook's HMAC signature against using `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), both fully attacker-controlled fields inside the unauthenticated JSON body. Once "verified" is true, the actual write-target repository/stack used by every event handler is resolved from a *different* payload field: `payload.dig('repository', 'full_name')` [1](#0-0) . In a multi-organization deployment (`config/secrets.yml` keyed by org, as documented) [2](#0-1) , any organization whose GitHub App is configured with `webhook_secret: nil` (explicitly documented as optional) causes `verify_webhook_signature` to short-circuit and return `true` unconditionally regardless of the request body [3](#0-2) .

### Finding Description
The trust chain is:
1. `verify_signature` derives `repository_owner` from the attacker-supplied JSON body and calls `Shipit.github(organization: repository_owner)` to pick a `GitHubApp` config [4](#0-3) .
2. `Shipit.github` looks up per-organization config via `github_app_config(organization)` [5](#0-4) .
3. `verify_webhook_signature` treats a blank `webhook_secret` as automatically verified: `return true unless webhook_secret` [3](#0-2) .
4. If `verified` is true, `create` dispatches the *entire* attacker-supplied JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) .
5. Every handler resolves the actual `Stack`/`Repository` to act on via `payload.dig('repository', 'full_name')` — a field that was never used in step 1's signature/organization selection [1](#0-0) , e.g. `PushHandler#process` triggers `stack.sync_github` [7](#0-6) , and PR handlers archive/unarchive review stacks or update pull requests [8](#0-7) .

This is the exact analog of the reported bug class: the field checked for trust (`repository.owner.login` → org used to pick the verifying secret) and the field acted upon (`repository.full_name` → the actual repository/stack that receives writes) are decoupled and both fully attacker-controlled. If any single organization sharing the Shipit instance has no `webhook_secret` configured — a state the setup docs explicitly present as a normal, optional choice — then an attacker can submit a forged JSON payload with `repository.owner.login` set to that unsecured organization while setting `repository.full_name` to point at a *different, secured* organization's stack, and `verify_webhook_signature` will pass unconditionally, letting the forged event execute writes (archiving/unarchiving review stacks, updating PR state, triggering `sync_github`) against a repository that was never actually authenticated.

### Impact Explanation
This allows an unauthenticated network attacker to perform unauthorized writes/state changes against stacks belonging to an organization whose secret was never validated, purely by targeting a co-tenant organization on the same Shipit instance that has a blank `webhook_secret`. This falls under "cross-repository writes" / "unauthorized... rollback" impact category, since handlers can archive review stacks, alter PR-derived state, and enqueue `GithubSyncJob`s that affect deploy eligibility for a repository the attacker never demonstrated control of.

### Likelihood Explanation
Exploitability is entirely conditioned on the specific multi-tenant configuration: it only manifests when (a) the instance is configured with multiple organizations via the per-org `github:` secrets format, and (b) at least one of those organizations has no `webhook_secret` set. Because `webhook_secret` is explicitly documented as optional for a *single*-org setup, and the multi-org example in the docs shows the same optional field per org, this is a plausible, not merely theoretical, operational configuration. However, it does not apply to the (likely more common) single-organization/single-app deployment, since there `github_default_organization` is `nil` and the same fixed secret is always used regardless of payload content [9](#0-8) .

### Recommendation
Do not select the verification key from attacker-controlled request-body fields when multiple organizations/secrets are configured; instead, use a per-organization webhook endpoint/URL segment (or another value not sourced from the JSON body) to pick the `GitHubApp`. Additionally, do not allow `webhook_secret` to be silently optional in multi-org configurations — require every configured organization to define a secret, and reject verification (rather than auto-pass) when it is missing in that context. Finally, cross-check that the organization used for verification matches the owner implied by `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `OrgUnsecured` (no `webhook_secret`) and `OrgTarget` (with a real `webhook_secret` and an active stack).
2. POST to `/webhooks` with header `X-Github-Event: push` and a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
     "owner": { "login": "OrgUnsecured" },
     "full_name": "OrgTarget/target-repo"
  }
}
```
No valid `X-Hub-Signature` header is required, since `repository_owner` resolves to `OrgUnsecured`, `Shipit.github(organization: 'OrgUnsecured')` returns a `GitHubApp` with a blank `webhook_secret`, and `verify_webhook_signature` returns `true` unconditionally [3](#0-2) .
3. `create` then dispatches the payload to `Shipit::Webhooks.for_event('push')`, and `PushHandler` resolves stacks via `Repository.from_github_repo_name('OrgTarget/target-repo')` [1](#0-0) [7](#0-6) , enqueuing a `GithubSyncJob` for `OrgTarget`'s stack without ever validating a signature tied to `OrgTarget`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
