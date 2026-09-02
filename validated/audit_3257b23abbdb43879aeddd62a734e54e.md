### Title
Webhook signature is authenticated per-organization while `StatusHandler` writes commit status by SHA alone, enabling cross-organization CI-status forgery and unauthorized continuous deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-tenant configuration where each GitHub organization has its own webhook secret [1](#0-0) . `WebhooksController#verify_signature` picks which organization's secret to validate the HMAC against using the *unauthenticated* payload field `repository.owner.login` (or `organization.login`) [2](#0-1) [3](#0-2) . Once the signature matches *that* organization's secret, the entire payload — including any other field, such as `sha` — is trusted and dispatched to handlers [4](#0-3) . `StatusHandler`, however, resolves the target `Commit` purely by `sha`, with no scoping to the repository/organization that was actually authenticated:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This breaks the binding: `organization authenticated by verify_signature == organization that owns the repository/commit being written`.

### Finding Description
In a multi-org Shipit deployment (`config/secrets.yml` keyed by organization, as documented and exercised by `test/dummy/config/secrets_double_github_app.yml`) [6](#0-5) , each organization has an independent `webhook_secret` used to create its own GitHub App and validate its own inbound webhooks [7](#0-6) .

`verify_signature` derives the organization used for HMAC verification straight from the JSON payload before any signature has been proven valid for that payload:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

This only proves the request body was signed with *some org's* secret — it says nothing about which repository's data inside that same body should be trusted. `StatusHandler#process` then updates any `Commit` in the entire Shipit instance that matches the attacker-supplied `sha`, with no re-derivation of `repository_owner`/`repository.full_name` and no check that the commit belongs to a stack under the organization that was actually authenticated [5](#0-4) . Compare this to other handlers that do scope by `repository.full_name` (e.g. `PushHandler`/`Handler#stacks`) [8](#0-7)  — `StatusHandler` omits this scoping entirely.

Equality that should hold but doesn't:
`organization authenticated in verify_signature (via repository.owner.login)` == `organization owning the Commit mutated by StatusHandler (via sha)`.

Before the attack: Org A's commit `abcdef123` has statuses set only by GitHub for Org A's CI. Org B is a legitimate, independently-configured tenant on the same Shipit instance, with its own valid `webhook_secret`.

After the attacker's request: an entity that only controls Org B's GitHub App/webhook secret submits a `status` event whose body is signed with Org B's secret (`repository.owner.login = "OrgB"`, satisfying `verify_signature`), but whose `sha` field is set to Org A's known commit SHA (commit SHAs are public/knowable information, especially for public repos or repos the attacker can read via other means). `StatusHandler` looks up `Commit.where(sha: "abcdef123")`, finds the Org A commit, and writes an arbitrary CI status (`state: "success"`, forged `context`) onto it, even though the signature only ever proved authorization for Org B.

### Impact Explanation
If Org A's stack has continuous deployment enabled and its `shipit.yml` declares `ci.require` contexts, a forged "success" status satisfying those required contexts can make an otherwise non-deployable commit appear deployable, causing Shipit's continuous delivery machinery to automatically ship it — an **unauthorized deploy** triggered entirely by an actor who never had any credential, session, or write access to Org A/its repository or Shipit stacks. This matches the report's High-impact category ("escalation ... resulting in an unauthorized deploy"). It also constitutes cross-tenant state corruption/writes (commit statuses of one org corrupted by another).

### Likelihood Explanation
Requires only administrative control of *any* organization's GitHub App/webhook secret already configured in the multi-org Shipit instance (i.e., possession of one tenant's own legitimate, low-privilege webhook signing capability — not privileged access to Shipit itself, not `GITHUB_TOKEN`, not an `ApiClient` token). Commit SHAs of a target repository are usually discoverable (public repos, PR references, CI logs, etc.), making the target `sha` guessable/obtainable without repository write access. This is Medium-High likelihood in any deployment that uses the documented multi-org configuration.

### Recommendation
`StatusHandler` (and any other handler resolving objects by non-repository-scoped identifiers) should always scope lookups through `stacks`/`Repository.from_github_repo_name(repository_name)` as `PushHandler` does, and/or `verify_signature` should re-validate, after establishing the org, that every repository-identifying field used downstream (`sha`'s owning stack, `repository.full_name`) actually belongs to the organization whose secret validated the signature.

### Proof of Concept
1. Attacker administers Org B's GitHub App in a Shipit instance configured with `github: { OrgA: {...}, OrgB: {...} }` (per `docs/setup.md` multi-org format).
2. Attacker learns Org A's commit SHA `deadbeef...` (e.g., from a public PR) that is currently pending on Org A's stack with CD enabled and `ci.require: ["some-context"]`.
3. Attacker crafts a `status` webhook JSON body:
```json
{ "sha": "deadbeef...", "state": "success", "context": "some-context",
  "repository": { "owner": { "login": "OrgB" } } }
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgB_webhook_secret, body)` using Org B's own known webhook secret and POSTs it to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` looks up `Shipit.github(organization: "OrgB")`, verifies successfully against `request.raw_post` [2](#0-1) .
6. `StatusHandler#process` executes `Commit.where(sha: "deadbeef...")`, finds Org A's commit, and calls `create_status_from_github!` writing the forged "success" status onto it [5](#0-4) .
7. If this satisfies Org A's stack's required CI checks, the next continuous-delivery cycle deploys the commit — an unauthorized deploy performed by an entity with no relationship to Org A.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
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
