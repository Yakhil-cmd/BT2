### Title
Webhook signature verification is keyed on `repository.owner.login` while all downstream handlers act on `repository.full_name`, allowing cross-repository event forgery when any configured GitHub App has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the secret used to validate `X-Hub-Signature`) using `repository.owner.login` taken directly from the untrusted JSON body, while every `Handler` (push, status, check_suite, pull_request, membership, ...) resolves the target `Stack`/`Repository` using `repository.full_name`, also taken from the same untrusted body. These two payload fields are never cross-checked against each other. Since Shipit explicitly supports multiple GitHub App configurations per instance (see `test/dummy/config/secrets_double_github_app.yml`) and `webhook_secret` is documented as optional, an attacker can pick any organization in the multi-tenant instance whose `webhook_secret` is blank to trivially satisfy signature verification, then set `repository.full_name` to a completely different, victim repository whose real GitHub App does have a proper secret.

### Finding Description
The verification flow is:
1. `verify_signature` derives the org from the payload and fetches its app config: [1](#0-0) 
2. `repository_owner` is read straight from the JSON body: [2](#0-1) 
3. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org has no `webhook_secret` configured: [3](#0-2) 
4. Once signature verification passes, `create` dispatches the *entire* payload — including `repository.full_name` — to the registered handlers: [4](#0-3) 
5. Each `Handler` resolves the acted-upon repository via `repository.full_name`, a field never covered by the org selected in step 1-3: [5](#0-4) 

`Shipit.github` supports exactly this multi-org topology by design: [6](#0-5) 

And the fixture used for tests demonstrates two apps configured side by side with `webhook_secret` left blank for both: [7](#0-6) 

The equality that should hold but doesn't: *the organization whose secret authenticated the request* == *the organization/repository whose stack state the handler mutates*. Because `repository_owner` (authentication key) and `repository.full_name` (mutation key) are read independently from the same attacker-controlled JSON body, and because signature verification degrades to an unconditional pass when any one org's `webhook_secret` is unset, an attacker who knows (or discovers) that some org in the instance has no secret configured can forge webhook events for any other repository hosted on the same Shipit instance, without ever possessing that other repository's real webhook secret.

### Impact Explanation
An attacker able to trigger this can:
- Forge `status` events to fabricate CI pass/fail state for a victim repository's commits (`app/models/shipit/webhooks/handlers/status_handler.rb` style handlers rely solely on `repository.full_name`), potentially unblocking merge/deploy gates that depend on commit status.
- Forge `check_suite`, `push`, `pull_request`, and `membership` events against arbitrary repositories/stacks tracked by the instance, causing spurious syncs, review-stack creation/archival, or team/user membership changes for organizations the attacker has no relationship with.
- This crosses a repository/authentication boundary without holding any real secret for the targeted repository, which is an authentication-bypass class issue reachable by any unauthenticated network attacker who can find (or brute-force/guess) an org in the instance configured without a webhook secret.

### Likelihood Explanation
Exploitability depends entirely on operator misconfiguration: at least one GitHub App entry in `secrets.github` must have a blank `webhook_secret`. This is explicitly supported and documented as optional ("Webhook secret (optional)" in `docs/setup.md`), and the engine ships a first-class multi-org test fixture exercising exactly this shape, so it is a realistic deployment topology rather than a purely theoretical one — but it does require this specific misconfiguration to exist somewhere in the instance's org list.

### Recommendation
Bind the two payload fields used for authentication and mutation together before dispatching to handlers: require that `repository.owner.login` (or `organization.login`) used to select the signing app match the organization portion of `repository.full_name` for every event, and reject the webhook otherwise. Additionally, consider refusing to boot / warning loudly when any configured GitHub App has a blank `webhook_secret` in a multi-org setup, since `verify_webhook_signature`'s `return true unless webhook_secret` effectively disables authentication for that org and, transitively, for any repository name an attacker chooses to embed in the payload.

### Proof of Concept
1. Deploy an instance configured with two GitHub Apps, e.g. `OrgAttacker` (no `webhook_secret`, per the pattern in `test/dummy/config/secrets_double_github_app.yml`) and `OrgVictim` (proper `webhook_secret`), each tracking their own repositories/stacks.
2. POST to `/webhooks` with `X-Github-Event: status` and any `X-Hub-Signature` value (or omit it), and a body such as:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "context": "ci/attacker-forged",
  "repository": {
    "owner": { "login": "OrgAttacker" },
    "full_name": "OrgVictim/victim-repo"
  }
}
```
3. `verify_signature` looks up `Shipit.github(organization: "OrgAttacker")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the supplied signature.
4. `StatusHandler` (or equivalent) resolves the target repository via `repository.full_name = "OrgVictim/victim-repo"` and records the forged status against `OrgVictim`'s stack, even though the request was never signed by `OrgVictim`'s app.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
