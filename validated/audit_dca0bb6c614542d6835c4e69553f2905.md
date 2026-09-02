### Title
Multi-organization webhook signature verification is keyed by the attacker-supplied `repository.owner.login`, and any org configured without a `webhook_secret` (a supported, sample-documented default) makes signature verification an unconditional pass for every repository - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which HMAC secret) to validate an inbound webhook against using `repository_owner`, a value read straight out of the unauthenticated JSON body, before the signature has been checked. [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats an unset `webhook_secret` as "always trusted": `return true unless webhook_secret`. [3](#0-2) 

The engine's own sample multi-org configurations ship with `webhook_secret` left blank/nil (`webhook_secret: # nil`), i.e. this is a documented, supported configuration shape, not a misuse of the engine. [4](#0-3) [5](#0-4) 

### Finding Description
This is the same bug class as the referral report: a field defaults to an "empty"/unset value (`_referred[user] == 0x0`, here `webhook_secret == nil`), and that default is treated by the lookup function as an unconditional match/trust ("all users route to referral 0x0", here "any payload routes to trust=true"). The attacker doesn't need to know a secret - they need only address the request at an organization slot that was left with the default (unset) value.

The equality that should hold but doesn't:
`organization that cryptographically authenticated the request == organization/repository whose state the handlers actually mutate`.

Concretely:
1. In multi-organization mode (`Shipit.github_default_organization` non-nil, i.e. `secrets.github` keyed by org names), `verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` directly from the attacker-controlled JSON body, and passes it to `Shipit.github(organization: repository_owner)`. [1](#0-0) 
2. `Shipit.github` resolves `github_app_config(organization)` by looking up that org key (case-insensitively) in `secrets.github`. [6](#0-5) 
3. If the resolved org's `webhook_secret` is blank (the sample/default configuration), `verify_webhook_signature` returns `true` with **no signature check at all** for that request. [3](#0-2) 
4. `#create` then dispatches the raw, attacker-controlled payload to the actual handlers, which derive the *target* repository/stack from a **different** field of the same payload — `payload.dig('repository','full_name')` — with no requirement that it match the org used for verification. [7](#0-6) [8](#0-7) 

So an attacker who knows (or guesses) the name of any organization slot in the instance's `secrets.github` that has no `webhook_secret` set can address `repository.owner.login` to that org name to make `verify_signature` pass unconditionally, while setting `repository.full_name` (and other handler fields) to point at a completely unrelated organization/repository/stack that they don't control.

### Impact Explanation
Once signature verification is bypassed this way, the attacker can forge any of the handled webhook event types against any stack in the instance, entirely unauthenticated:
- `StatusHandler` accepts attacker-controlled `sha`, `state`, `description`, `target_url`, `context` and calls `commit.create_status_from_github!(params)`, letting the attacker fabricate a `success` CI status for a specific commit on someone else's stack. [9](#0-8) 
- `PushHandler` can trigger `stack.sync_github(expected_head_sha: ...)` for a targeted branch/stack. [10](#0-9) 

Since Shipit's merge queue and continuous-deployment logic rely on GitHub commit statuses/checks to gate merges and deploys, injecting forged "success" statuses for arbitrary commits on stacks outside the attacker's own organization is a path to an **unauthorized merge/deploy**, satisfying the Critical bar in scope ("an unauthorized deploy, rollback or merge"). This crosses the organizational trust boundary the multi-app configuration is meant to enforce (`docs/setup.md`'s "Using Multiple Github Applications" section) without requiring any Shipit session, API token, or the real per-organization webhook secret. [11](#0-10) 

### Likelihood Explanation
Likelihood depends on operational configuration: it requires an instance running in multi-organization mode (`secrets.github` keyed by multiple org names) where at least one configured organization has no `webhook_secret` set. This is not a hypothetical edge case — every sample/dummy config shipped in the repo for multi-org setups leaves `webhook_secret` blank/nil, so it is a realistic default state during setup or for lower-stakes orgs, and the code path treats that default as full trust rather than failing closed.

### Recommendation
- In `GitHubApp#verify_webhook_signature`, fail closed (return `false`) when `webhook_secret` is blank, instead of returning `true`.
- Bind the signature-verifying organization to the same value handlers use to locate the target repository/stack (e.g. verify against `payload.dig('repository','full_name')`'s owner, not a separately-fetched field), or re-derive/re-validate the organization after signature verification and reject if it doesn't match the org whose secret validated the request.
- Require `webhook_secret` to be present for every organization in multi-app mode, and refuse to boot / raise a configuration error if it's missing, rather than silently degrading to "always trusted."

### Proof of Concept
1. Operator configures `secrets.github` with two orgs, e.g. `victim-org` (a real webhook_secret) and `test-org` (webhook_secret left blank, as shown in `config/secrets.development.shopify.yml`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "test-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "test-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `StatusHandler#process` runs against `victim-org/victim-repo`'s commit, recording a forged `success` status that can satisfy merge/deploy gating for a repository the attacker has no access to.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

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
