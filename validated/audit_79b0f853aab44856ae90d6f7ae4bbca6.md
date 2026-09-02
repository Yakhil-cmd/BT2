### Title
Webhook organization used for signature verification is decoupled from the repository whose Stack state is mutated - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `repository_owner`, but the handlers that actually mutate application state (commit statuses, stacks, review-stack labels, sync jobs) resolve the target `Repository`/`Stack` from a separate field, `repository.full_name`, taken from the very same attacker-suppliable JSON body. Because the whole request body is attacker-controlled (the endpoint is unauthenticated except for the HMAC check), an actor who knows the webhook secret for one onboarded GitHub organization can forge a payload whose `repository.owner.login` matches "their" organization (so the signature check passes) while `repository.full_name` names a completely different organization/repository that is also tracked by the same Shipit instance, causing cross-repository writes.

### Finding Description
The signing organization is chosen here: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and `Shipit.github(organization: repository_owner)` is used only to fetch the `webhook_secret` for that organization to validate `X-Hub-Signature`.

Once the signature "passes" for that chosen org, the entire raw payload (unchanged) is dispatched to every registered handler for the event: [3](#0-2) 

Handlers, however, resolve the affected `Repository`/`Stack` from a *different* field of the same payload — `repository.full_name` — not from `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this attacker-controlled string on `/` and looks up any existing `Repository` record by owner/name, with no re-validation that it matches the organization that was authenticated: [5](#0-4) 

The `GitHubApp` (and hence `webhook_secret`) is explicitly a per-organization construct, confirming this is a legitimate multi-tenant deployment shape supported by the engine (multiple orgs, each with its own app/secret, on one Shipit instance): [6](#0-5) [7](#0-6) [8](#0-7) 

Because `repository.owner.login` and `repository.full_name` are two independently-readable fields inside a single JSON object that the attacker fully controls (subject only to producing a valid HMAC for whichever org they pick), nothing in `verify_signature` or in `Handler#repository_name`/`Repository.from_github_repo_name` enforces that `repository.owner.login == repository.full_name.split('/').first`. This is exactly the "organization that authenticated versus the repository that is written" binding called out as a break-worthy pattern: before the attack, `signing_org == written_repo.owner` is assumed to hold for all legitimate GitHub-originated webhooks; after a forged request, `signing_org` (attacker's own org, whose secret they know) can be made to diverge arbitrarily from `written_repo.owner` (a victim org/repo tracked by the same Shipit deployment).

### Impact Explanation
An attacker who is a legitimate administrator of one GitHub organization/repository tracked by a shared Shipit instance (and therefore knows or controls that org's `webhook_secret`) can forge webhook deliveries that are cryptographically "valid" for their own org while carrying a `repository.full_name` pointing at a different, victim-owned repository/stack also hosted on the same Shipit instance. Depending on the handler invoked this enables, without any credential for the victim org:
- Injecting/forging commit `status` events for the victim repository's commits, which can flip `deploy_state`/`deployable?` from blocked to allowed and enable an **unauthorized deploy** of the victim stack (statuses directly feed `Stack#deployable?` gating, per `app/models/shipit/stack.rb`).
- Triggering `GithubSyncJob`/`RefreshCheckRunsJob` and pull-request label/archive handlers (`PullRequest::UnlabeledHandler`, `OpenedHandler`, etc.) against the victim repository's review stacks, causing cross-repository state changes that should only be triggerable by GitHub events genuinely originating from that repository.

This matches the "Critical: cross-repository writes / unauthorized deploy" impact bar.

### Likelihood Explanation
This requires the Shipit instance to be configured for more than one GitHub organization (a documented, supported configuration, cf. `secrets_double_github_app.yml`) and requires the attacker to control (or be an admin of) at least one of those organizations well enough to know its webhook secret — which is exactly the kind of "authenticated but wrong scope" actor the rules ask to consider, not a fully external unauthenticated attacker. No GitHub App private key, Shipit `ApiClient` token, or Shipit session is needed; only knowledge of one tenant org's webhook secret and the ability to POST an arbitrary JSON body to the public `/webhooks` endpoint.

### Recommendation
After signature verification selects `repository_owner`/organization, re-derive and cross-check the repository/organization used by handlers from the same authenticated field, rejecting requests where `repository.full_name`'s owner segment does not match the organization whose secret validated the signature (or, better, verify the signature per-repository using the secret bound to the `Repository` resolved from `full_name`, rather than a secret chosen from an unrelated field of the untrusted payload).

### Proof of Concept
1. Shipit instance is configured with two GitHub App tenants, `OrgA` (attacker-administered, webhook secret known to attacker) and `OrgB` (victim, tracks stack `orgb/victim-repo`), as in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `status` webhook JSON body:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s known `webhook_secret` over this exact raw body and sends it to `POST /webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner => "orga"`, fetches `OrgA`'s app, and the HMAC check succeeds (attacker controls the secret).
5. `create` dispatches the payload to the `status` handler, which resolves the target repository via `payload.dig('repository', 'full_name') => "orgb/victim-repo"` (per `Handler#repository_name`/`Repository.from_github_repo_name`) and records the forged `success` status against the victim's commit, independent of the `OrgA` signature scope — enabling the victim stack to become deployable/mergeable based on attacker-forged CI state.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
