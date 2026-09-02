### Title
Webhook signature verification is bound to an attacker-controlled `organization`/`repository.owner` field while the write path acts on an independently attacker-controlled `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `repository_owner`, a value read directly out of the untrusted JSON body. The actual mutation performed by every webhook handler (`Handler#stacks`) selects the target `Repository`/`Stack` using a *different* field from the same untrusted body: `repository.full_name`. Because these two fields are never checked for consistency, and because a webhook secret is documented as optional per organization, an attacker can produce a request that is "verified" against one (weakly- or un-secured) organization while it actually mutates stacks belonging to a completely unrelated, victim organization/repository.

### Finding Description
`verify_signature` derives the signing organization solely from payload content: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization, which the setup docs explicitly mark as **optional**: [3](#0-2) [4](#0-3) 

Once "verified", the controller dispatches the raw, attacker-supplied JSON straight to the handlers: [5](#0-4) 

Every handler then resolves *which repository/stack to act on* using a field that was never covered by the signature check that mattered (`repository.owner.login`/`organization.login`): [6](#0-5) 

For example, `PushHandler` triggers a GitHub sync against every non-archived stack of whatever repository `repository.full_name` names: [7](#0-6) 

and `PullRequest::ClosedHandler` resolves the repository the same way and can archive review stacks belonging to it: [8](#0-7) 

The binding that should hold is:
`organization whose secret validated the signature == owner of the repository whose Stacks are mutated`

But the code only enforces:
`organization whose secret validated the signature == payload["repository"]["owner"]["login"] (or payload["organization"]["login"])`

and separately, unconditionally:
`repository acted upon == payload["repository"]["full_name"]`

Since both values come from the same attacker-controlled JSON body and are never cross-checked against each other, an attacker can decouple them: supply an `organization.login`/`repository.owner.login` that resolves to an organization configured in Shipit with `webhook_secret` unset (a supported, documented configuration — see `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.example.yml`, both showing `webhook_secret: # nil` as valid per-org config), while setting `repository.full_name` to an entirely different, victim organization's repository. [9](#0-8) [10](#0-9) 

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated versus the repository that is written." An unprivileged attacker who never delivered a real GitHub webhook, holds no `webhook_secret`, no `api_clients_secret`, and no Shipit session, can:
- Trigger unauthorized `GithubSyncJob`s and archive review stacks for a victim repository they have no relationship to (`PushHandler`, `ClosedHandler`).
- Depending on which handlers are registered (status/check_run handlers write `Status`/check-run records consumed by merge/deploy safety checks), influence merge-queue and deploy-safety state for a repository the attacker does not own — a cross-repository write with no repository access required.

This lands in the Critical/High bracket described by the rules (cross-repository writes / unauthorized state mutation feeding into merge/deploy decisions), reached purely by crafting an HTTP POST to the public `/webhooks` endpoint.

### Likelihood Explanation
Exploitability depends on the deployment having at least one configured GitHub organization with `webhook_secret` left blank (explicitly supported/documented as optional) or on an attacker who can otherwise obtain a validly-signed payload for any one organization in a multi-org install. Given that the "optional" secret is a first-class supported configuration path (not a misconfiguration outside documented use), this is a realistic exposure for any multi-tenant Shipit deployment, hence rated Medium-High likelihood.

### Recommendation
Do not select the signature-verification key from attacker-supplied payload fields that are disjoint from the field used to select the mutation target. Concretely:
1. In `Shipit::WebhooksController#verify_signature`, once the app/secret for a given `repository_owner` is resolved and the signature verified, re-derive `repository_owner` from `payload.dig('repository', 'full_name')`'s owner segment (the exact same field `Handler#repository_name` uses) rather than from the independent `owner.login`/`organization.login` fields, or explicitly assert equality between them before dispatch.
2. Require `webhook_secret` to be present for every configured organization (fail closed rather than `return true unless webhook_secret`), removing the trivially bypassable verification path.

### Proof of Concept
Assume a multi-org Shipit install where `AttackerOrg` is configured with no `webhook_secret` (supported per `docs/setup.md`) and `VictimOrg/victim-repo` is a real, unrelated stack in the same Shipit instance.

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json
X-Hub-Signature: sha1=anything-or-empty

{
  "organization": { "login": "AttackerOrg" },
  "repository": { "full_name": "VictimOrg/victim-repo" },
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```

- `repository_owner` resolves to `"AttackerOrg"` (no `repository.owner.login`, falls back to `organization.login`).
- `Shipit.github(organization: "AttackerOrg").verify_webhook_signature` returns `true` immediately because `AttackerOrg` has no `webhook_secret`.
- `WebhooksController#create` dispatches the parsed body to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("VictimOrg/victim-repo")` and calls `sync_github` on all of `VictimOrg`'s stacks — a write triggered by an entity with zero relationship to `VictimOrg`. [5](#0-4) [6](#0-5)

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
