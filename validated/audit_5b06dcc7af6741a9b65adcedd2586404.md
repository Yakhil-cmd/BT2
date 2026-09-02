### Title
Handler/WebhooksController never binds the org that verified the HMAC to the `repository.full_name` namespace Handler#stacks resolves against - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` used for HMAC verification from `repository.owner.login`, while `Handler#stacks` resolves the target `Stack` from the independent, attacker-controlled `repository.full_name` field. No code anywhere cross-checks that these two payload fields agree, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org's `webhook_secret` is unset (a state explicitly supported and documented as "optional"). In a multi-tenant Shipit install, this lets an attacker who can reach `POST /webhooks` forge events against any other tenant's repository by naming an unsecured org as owner and a victim org's repo as `full_name`.

### Finding Description
The binding the question describes should be: `organization_that_verified_HMAC(payload) == namespace_prefix(payload['repository']['full_name'])`. Tracing the code shows these two values are derived independently and never compared:

- `WebhooksController#repository_owner` reads `params.dig('repository','owner','login')` and is used only to select which `GitHubApp` verifies the signature: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 

- `Handler#repository_name`/`#stacks` reads a completely different field, `payload.dig('repository','full_name')`, with no reference to which org's app verified the request: [3](#0-2) 

- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected org's config has no `webhook_secret`: `return true unless webhook_secret`. [4](#0-3) 

- The engine explicitly supports and documents multiple, independently-configured GitHub Apps keyed by organization, each with its own optional `webhook_secret` (see `Shipit.github_app_config`/`Shipit.github_organizations` and the multi-org fixture with per-org `webhook_secret:` left blank). [5](#0-4) [6](#0-5) 

Exploit flow: in a multi-tenant Shipit deployment where org `unsecured-org` has no `webhook_secret` configured (explicitly documented as optional in `docs/setup.md`), an unauthenticated attacker sends `POST /webhooks` with header `X-Github-Event: push` and a JSON body such as `{"repository":{"owner":{"login":"unsecured-org"},"full_name":"victim-org/victim-repo"}, "after": "<sha>", "ref":"refs/heads/master", ...}` and any/no `X-Hub-Signature`. `verify_signature` looks up `Shipit.github(organization: "unsecured-org")`, calls `verify_webhook_signature`, which returns `true` unconditionally because that org's `webhook_secret` is blank. The request proceeds, `Handler.call(params)` runs, and `Handler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and its real `Stack` records - fully decoupled from the org that "verified" the request.

Existing guards do not close this gap: `verify_signature`/`verify_webhook_signature` only prove the request was signed by *some* configured org's secret (or that the org has no secret at all); they never assert that org matches `repository.full_name`'s prefix. `Repository` model validations only check `owner`/`name` character-class/length format, not that the owner matches an authenticated app. `ExplicitParameters` schemas in the various handlers only validate presence/type of fields, not cross-field org binding.

### Impact Explanation
A successful request lets an unauthenticated attacker inject forged GitHub events (`push`, `status`, `check_suite`, `pull_request`, `deployment`, etc.) that are processed as if genuinely originating from `victim-org/victim-repo`, mutating that stack's/commit's/task's state (e.g., queuing `GithubSyncJob`, writing `Status`/`CommitDeploymentStatus` records, or driving PR-labeling handlers) even though the verifying organization has nothing to do with the victim repository. This is a cross-tenant "payload for one repository mutating another's stack/commit/task" scenario, matching the Critical impact category, and is repeatable against any repository/stack configured on the host as long as one org in the multi-app config has no `webhook_secret` set.

### Likelihood Explanation
Requires: (1) the Shipit installation uses the multi-organization GitHub App schema (`secrets.github` keyed by org names, as shown supported in `lib/shipit.rb`), and (2) at least one configured org has its `webhook_secret` left blank — a state the project's own setup docs call "optional" and therefore realistic in production. Given those preconditions, the attack costs the attacker nothing (no secrets, no session, no repository ownership needed) and is trivially repeatable via any HTTP client. The likelihood is conditional on operator configuration but is a direct consequence of the engine's own code (`return true unless webhook_secret`) combined with the missing cross-field binding, not on any external secret compromise.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler#initialize`/`#stacks`), enforce that the organization whose `GitHubApp` verified the webhook signature equals the owner/namespace prefix parsed from `payload['repository']['full_name']` (and reject/log if they diverge), and consider making `webhook_secret` mandatory (raising at boot/config-load time) rather than silently trusting unsigned payloads when it is blank.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`), using the multi-org fixture pattern already present in `test/dummy/config/secrets_double_github_app.yml`:
1. Configure `secrets.github` with two orgs: `unsecured-org` (no `webhook_secret`) and `victim-org` (has a `Stack`/`Repository` fixture, e.g. `shipit_stacks(:shipit)` under owner `victim-org`).
2. `POST :create` with `X-Github-Event: push`, no/garbage `X-Hub-Signature`, and body `{"repository": {"owner": {"login": "unsecured-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/master", "after": "<sha>"}`.
3. Assert `response` is `:ok` (not `:unprocessable_entity`), proving `verify_signature` passed via `unsecured-org`'s config equality `organization_that_verified_HMAC == "unsecured-org"`.
4. Assert a job/record was enqueued/written against `victim-org/victim-repo`'s real `Stack` (e.g. `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, ...])`), proving `namespace_prefix(full_name) == "victim-org"` — demonstrating the two sides of the equality diverge (`"unsecured-org" != "victim-org"`) while the request still succeeds and mutates the victim stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

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
