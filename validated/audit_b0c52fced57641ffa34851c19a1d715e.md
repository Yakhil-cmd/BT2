### Title
Webhook signature is verified against the GitHub organization inferred from an unauthenticated field, while the event handlers act on a different, unauthenticated `repository.full_name` field in the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Every downstream webhook handler, however, identifies the `Repository`/`Stack` to act on using a *different* field from the very same body: `repository.full_name`. Nothing enforces that these two attacker-supplied fields describe the same repository, so the org whose secret is used to *authenticate* the request can be made to diverge from the repository that is actually *written to*.

### Finding Description
`verify_signature` picks the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks the org up (case-insensitively) in `secrets.github`, which the docs explicitly support as a multi-tenant map of `{org => {webhook_secret, app_id, ...}}`: [3](#0-2) [4](#0-3) 

Signature verification itself is `return true unless webhook_secret` when that org has no secret configured, i.e. HMAC checking is silently skipped: [5](#0-4) 

Once the (possibly nil/skipped) check for `repository_owner` passes, `create` re-parses the same raw body and hands it to every registered handler unmodified: [6](#0-5) 

All the handlers (push, pull_request family, membership, check_suite, status) resolve the actual `Stack`/`Repository`/`ReviewStack` to mutate from `payload.dig('repository', 'full_name')`, a completely separate field from the one used for authentication: [7](#0-6) [8](#0-7) [9](#0-8) 

`repository.owner.login` and `repository.full_name` are never cross-checked. This is analogous to the "365.25 days vs 365 days" report's root cause: two logically-coupled quantities that should be derived from a single trusted source are instead computed independently — here, the field bound by the cryptographic signature (`repository_owner`) is never the field the effectful code (`repository.full_name`) actually consumes.

### Impact Explanation
On a Shipit installation configured for multiple GitHub organizations (a supported, documented configuration), an attacker who knows or controls the `webhook_secret` of *any one* configured organization (e.g. their own low-value org onboarded on the same instance, or any org whose secret is left blank) can forge a request where:
- `repository.owner.login` / `organization.login` = the org whose secret they know (used only to pass `verify_signature`), and
- `repository.full_name` = `victim-org/victim-repo` (used by the actual handler).

This lets the attacker trigger authenticated-looking webhook side effects against a repository/organization they have no legitimate access to — e.g. forcing `GithubSyncJob` on a victim stack, opening/closing/archiving `ReviewStack`s, injecting fabricated commit `Status`/`check_suite` results consumed by deploy safety checks, or creating/removing `Membership`/`Team` records — all cross-organization, unauthenticated writes into state that other, legitimate deploy/rollback decisions in Shipit rely on.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (explicitly documented and supported), and (2) attacker knowledge of a `webhook_secret` for at least one configured org, or one configured org with a blank secret (which the code explicitly tolerates via `return true unless webhook_secret`). Given orgs are commonly onboarded with differing operational rigor (test/sandbox orgs vs. production orgs) on a shared Shipit instance, this is a realistic misconfiguration/abuse path rather than a purely theoretical one.

### Recommendation
Do not select the signature-verification secret from unauthenticated payload data at all if it will be trusted to authorize actions on a different payload field. At minimum, after signature verification succeeds, re-derive `repository_owner` from `repository.full_name`'s prefix (or vice versa) and reject the request (422) if the two disagree. Longer term, verify the signature using every configured organization's secret (or key on `X-GitHub-Hook-Installation-Target-ID`/App ID rather than attacker-controlled JSON) so the same untrusted field can't simultaneously select the trust anchor and the target of the mutation.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `attacker-org` (attacker knows/owns `webhook_secret_A`, or leave it blank) and `victim-org` (protected `webhook_secret_B`), per the supported multi-org schema.
2. Attacker sends `POST /github` (webhooks endpoint) with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { "...": "..." },
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sender": { "login": "attacker" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac using webhook_secret_A>` over the exact raw body.
4. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `webhook_secret_A`, and validates successfully (or skips validation entirely if `attacker-org` has no secret) — see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62` and `lib/shipit/github_app.rb:76-83`.
5. `OpenedHandler#repository` resolves `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` and creates/mutates a `ReviewStack` under `victim-org`, per `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54` and `app/models/shipit/repository.rb:53-56` — despite the request never being signed by `victim-org`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
