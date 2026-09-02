## Title
Cross-organization signature confusion in `WebhooksController#verify_signature` allows forged webhooks to mutate stacks belonging to a different GitHub organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-tenant deployments, `Shipit.github(organization:)` resolves the `GitHubApp` (and its `webhook_secret`) used to *verify* an incoming webhook from the attacker-controlled `repository.owner.login` (or `organization.login`) field of the same unverified payload [1](#0-0) . Once the signature check passes, the actual event handlers resolve the target `Repository`/`Stack` using a *different* field of the same payload, `repository.full_name` [2](#0-1) . Nothing binds the organization whose secret validated the signature to the organization actually written to.

### Finding Description
`verify_signature` picks the `GitHubApp` config (and thus the `webhook_secret` HMAC key) via:
```ruby
github_app = Shipit.github(organization: repository_owner)
```
where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [3](#0-2) . This is a value taken from the *unverified* JSON body — the signature has not been checked yet at this point.

The signature itself is HMAC'd over the entire raw body using that organization's `webhook_secret`, per `GitHubApp#verify_webhook_signature` [4](#0-3) . Shipit explicitly documents and supports hosting multiple, independently-secreted GitHub App installations for different organizations in one instance via `config/secrets.yml` (`Shipit.github_app_config`, `TOP_LEVEL_GH_KEYS`) [5](#0-4) , confirmed by `docs/setup.md`'s "Using Multiple Github Applications" section and the test fixture `test/dummy/config/secrets_double_github_app.yml` defining `OrgOne` and `OrgTwo` with distinct secrets.

Once `verify_signature` succeeds (using OrgB's secret because `repository.owner.login == "OrgB"`), `WebhooksController#create` dispatches to handlers with the raw parsed payload [6](#0-5) . Handlers such as `Handler#stacks`/`#repository_name` and the `PullRequest` handlers locate the target `Repository` using `payload.dig('repository', 'full_name')` / `params.repository.full_name` — a completely independent field of the same JSON body [2](#0-1) [7](#0-6) . `Repository.from_github_repo_name` splits this string on `/` and does a straight DB lookup with no cross-check against the organization used for verification [8](#0-7) .

**Equality the fix must preserve:** organization whose `webhook_secret` authenticated the HMAC == organization of the `repository.full_name` that handlers act on. Today this equality is never enforced — `repository.owner.login` (verification key selector) and `repository.full_name` (state-mutation target) are two independently attacker-controlled strings in the same JSON body, and the code never asserts they refer to the same organization.

### Impact Explanation
An attacker who legitimately administers (or has webhook access to) one tenant organization ("OrgB", with a real, distinct `webhook_secret` configured in the shared Shipit instance) can compute a valid HMAC-SHA1 signature over an arbitrary payload using OrgB's secret, then set that payload's `repository.full_name` to `OrgA/some-repo` while keeping `repository.owner.login` (or `organization.login`) equal to `OrgB` so the correct-but-wrong-scope secret is selected and validated. The forged, correctly-signed request is then processed against `OrgA`'s stacks — e.g. triggering `GithubSyncJob` on `push`, creating commit statuses, or manipulating pull-request/review-stack state for repositories the attacker has no access to. This is a cross-repository/cross-organization write achieved without ever possessing OrgA's actual GitHub credentials, satisfying the "cross-repository writes" Critical-impact criterion for a multi-org Shipit deployment.

### Likelihood Explanation
Requires: (1) the Shipit instance hosting at least two organizations with independent GitHub Apps (a documented, supported configuration, not a misconfiguration), and (2) the attacker controlling one org's legitimate webhook delivery (i.e., knowing that org's `webhook_secret`, as any admin of that org's installed GitHub App would). Given that precondition, the exploit itself is a single crafted HTTP POST with no other privilege required — no session, no `ApiClient` token, no GitHub token for the target org.

### Recommendation
Bind verification and processing to the same organization: after selecting `github_app` by `repository_owner` and validating the signature, re-derive the organization from `repository.full_name` used by the handlers and reject the request (`head(422)`) if it does not match `repository_owner`/the app used for verification. Alternatively, always verify using the app for the organization implied by `repository.full_name` (the actual mutation target) rather than a separately-read `repository.owner.login`/`organization.login` field.

### Proof of Concept
1. Shipit configured with two orgs, `OrgA` (target, secret `secretA`, unknown to attacker) and `OrgB` (attacker-administered installation, secret `secretB`, known to attacker).
2. Attacker builds a `push` payload:
```json
{
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/target-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(secretB, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgB")` (from `repository.owner.login`), validates the HMAC against `secretB` successfully [1](#0-0) .
5. `WebhooksController#create` dispatches to `PushHandler`, which resolves the target stack via `repository.full_name = "OrgA/target-repo"` [2](#0-1) , enqueuing `GithubSyncJob` / mutating `OrgA`'s stack state despite the attacker never possessing `OrgA`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L33-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
