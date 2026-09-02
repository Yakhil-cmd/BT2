### Title
Webhook signature verification is keyed on `repository.owner.login` while write actions are keyed on `repository.full_name` from the same unauthenticated payload, allowing cross-organization webhook forgery when any configured GitHub org has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated request body. Every webhook handler, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same payload, `repository.full_name` [1](#0-0) . Because `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that organization [2](#0-1) , an attacker only needs one configured organization in a multi-org Shipit deployment to have a blank/optional `webhook_secret` (explicitly documented as optional) to bypass signature verification entirely, while still causing the handler to act on a repository/stack belonging to a completely different, secret-protected organization.

### Finding Description
The trust binding that should hold is: `organization whose secret authenticated the request == organization owning the repository actually written to`. This binding is broken:

1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses it solely to pick the `Shipit.github(organization: repository_owner)` app/secret for HMAC verification [3](#0-2) [4](#0-3) .
2. If that organization's config has no `webhook_secret` set (a supported, documented configuration - "Webhook secret (optional)" [5](#0-4) , also shown with `webhook_secret: # nil` in example configs [6](#0-5) ), `verify_webhook_signature` short-circuits to `true` regardless of the signature header content [7](#0-6) .
3. Once verification passes, the raw JSON body is dispatched to handlers unchanged: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [8](#0-7) .
4. Every handler (e.g. `PushHandler`) resolves the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')` - a field completely independent from the `repository.owner.login` used in step 1 - and then performs a mutating action, e.g. `stack.sync_github(expected_head_sha: params.after)` [9](#0-8) [1](#0-0) .

Since the same top-level JSON blob supplies both the "authenticating" field (`repository.owner.login`) and the "acted-upon" field (`repository.full_name`), and nothing cross-checks that the two refer to the same organization, an attacker can set `repository.owner.login` to the unsecured org (to trivially pass verification) while setting `repository.full_name` to `secured-org/some-repo` (to target a different, secret-protected organization's stack). This is structurally the same "double-counting"/mismatched-field root cause as the referenced dTRINITY report: two values that should be tied together by validation are instead independently attacker-controlled, and only one of them is meaningfully checked.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary called out in scope. Concretely, in any multi-org Shipit deployment (`docs/setup.md` "Using Multiple GitHub Applications" section [10](#0-9) ) where at least one configured org omits `webhook_secret`, an unprivileged external attacker (no GitHub App credentials, no Shipit session, no `ApiClient` token) can forge arbitrary webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) that are processed as if they legitimately originated from a different, secret-protected organization's repository. Depending on the handler this can force `GithubSyncJob`/`RefreshCheckRunsJob` enqueuing, create bogus commit `Status` rows, or manipulate team membership records tied to that other organization's stacks - undermining the state Shipit uses to gate continuous deployment and merge queue decisions.

### Likelihood Explanation
Likelihood depends on operator configuration: it requires a multi-org Shipit install where at least one org's `webhook_secret` is left blank (an explicitly supported/documented option). This is a realistic and encouraged configuration path (the setup docs call the webhook secret "optional"), and requires no attacker credentials, network position, or social engineering - just crafting an HTTP POST to `/webhooks` with a chosen JSON body.

### Recommendation
When selecting the organization to verify a webhook's signature against, cross-validate that `repository.owner.login`/`organization.login` matches the organization implied by `repository.full_name` before dispatching to handlers, and reject the request otherwise. Additionally, consider disallowing/deprecating unset `webhook_secret` for any organization in multi-org deployments, or requiring all configured organizations to be either fully secured or entirely disabled for webhook processing to avoid a single unsecured org acting as a bypass for others.

### Proof of Concept
Preconditions: `config/secrets.yml` configured with multiple GitHub orgs (per `docs/setup.md`), where `orgA.webhook_secret` is blank and `orgB.webhook_secret` is set, and a Shipit `Stack` exists for `orgB/some-repo`.

1. Attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/some-repo"
  }
}
```
2. `verify_signature` resolves `repository_owner` to `"orgA"`, fetches `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking `X-Hub-Signature` at all [2](#0-1) .
3. `PushHandler` resolves `repository_name` to `"orgB/some-repo"` and enqueues a sync for that stack, even though the attacker never possessed `orgB`'s webhook secret [9](#0-8) .

Note: I was unable to fully inspect `status_handler.rb` and `membership_handler.rb` contents (only located them via `glob_search`) before running out of tool iterations, so I cannot conclusively confirm which specific handler yields the highest-severity impact (e.g., forged CI "success" statuses feeding continuous-deployment auto-triggers, or forged membership/team changes). The root-cause binding break in `webhooks_controller.rb`/`handler.rb` demonstrated above is confirmed directly from source, but a full enumeration of exploitable downstream handlers would benefit from a deeper session reading those two files in full.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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
