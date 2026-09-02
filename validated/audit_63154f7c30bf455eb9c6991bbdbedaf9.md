### Title
Webhook signature verification is bound to the payload's `repository.owner.login`, but `StatusHandler` writes GitHub check statuses using a globally-unscoped commit `sha` lookup, allowing cross-organization status forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the HMAC secret) to verify a webhook against using `repository_owner`, a field read straight out of the untrusted JSON body [1](#0-0) . In multi-org Shipit deployments each organization has its own, individually-optional `webhook_secret` [2](#0-1) . `GitHubApp#verify_webhook_signature` treats a blank secret as "always verified" [3](#0-2) . Once verification passes, `Shipit::Webhooks::Handlers::StatusHandler` never checks which organization/repository was actually authenticated - it looks up commits globally by `sha` across the entire Shipit instance and writes a CI status onto them [4](#0-3) . The binding "organization that authenticated the webhook" ≠ "repository/commit that gets written" is exactly the class of check-the-wrong-field bug described in the report (checking `yieldBearingToken` instead of `backingToken`).

### Finding Description
The controller's only authentication gate is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`Shipit.github(organization:)` resolves per-organization config, and `verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank (an explicitly documented, optional setting) [3](#0-2) [6](#0-5) .

Once the `create` action is reached, event handlers are dispatched with the raw, attacker-controlled JSON `params` [7](#0-6) . Unlike the base `Handler`, which scopes lookups through `Repository.from_github_repo_name(repository_name)` (itself derived from `payload.dig('repository','full_name')`, a second, independently-attacker-controlled field) [8](#0-7) , `StatusHandler` bypasses this scoping entirely:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

`Commit.where(sha: params.sha)` is a global, unscoped ActiveRecord lookup across every stack/repository tracked by the Shipit instance - it never checks that the matched commit belongs to the organization/repository that the signature was verified against. The equality this breaks is:

`organization used to select the verification secret (payload.repository.owner.login)` ≠ `repository/commit whose status record is actually mutated (any Commit matching payload.sha, instance-wide)`

### Impact Explanation
An unprivileged attacker who knows (a) the public `/webhooks` endpoint and (b) the name of any organization configured in this Shipit instance with a blank/unset `webhook_secret` (an explicitly supported, documented configuration) can send a forged `status` event where `repository.owner.login` names that unsecured organization, while `sha` targets a commit belonging to a completely different, secret-protected organization's stack. Because verification passes trivially for the unsecured org, and `StatusHandler` never re-checks repository ownership, the attacker can inject an arbitrary CI status (`state`, `description`, `target_url`, `context`) onto a commit in a stack they have no relationship to. Since Shipit workflows commonly gate merges/deploys on commit status, this allows an unauthorized party to forge a passing status on a target repository's commit, undermining deploy/merge safety checks without ever needing repository write access, an `ApiClient` token, or the target organization's `webhook_secret`.

### Likelihood Explanation
Likelihood is elevated by the fact that the webhook secret is explicitly optional per organization in Shipit's official setup docs, and multi-org deployments are a first-class supported configuration [2](#0-1) . Any single organization onboarded without a webhook secret (or an admin who left it blank while testing) becomes a signing oracle usable to inject unscoped writes against every other organization's commits, requiring no credentials at all.

### Recommendation
`StatusHandler#process` (and any other handler that does not go through `Handler#stacks`) should scope its `Commit` lookup to the repository identified by the verified organization, e.g. join through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and confirm its owner matches `repository_owner`, mirroring the base `Handler` scoping. Additionally, `verify_webhook_signature` should not silently allow unsigned requests when `webhook_secret` is blank for one organization while other organizations require it - at minimum, `repository_owner` should be cross-checked against `repository.full_name`'s owner segment before selecting which secret to verify against.

### Proof of Concept
1. Deploy Shipit with two organizations configured: `orgA` (`webhook_secret: nil`) and `orgB` (`webhook_secret: <strong-secret>`), each hosting stacks tracked by this instance.
2. Attacker, with no credentials, sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything   # ignored, orgA has no secret
{
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/throwaway"},
  "sha": "<sha of a real commit belonging to an orgB-owned stack>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://attacker.example"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (bogus) `X-Hub-Signature` [3](#0-2) .
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the orgB commit (global lookup, no repository/org scoping), and calls `create_status_from_github!`, writing a forged "success" status onto an orgB commit the attacker never authenticated against [4](#0-3) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
