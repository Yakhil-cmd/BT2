## Finding

### Title
Webhook signature verification uses a different repository/organization field than the one handlers act on, allowing forged GitHub events for any tracked stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC against using `repository_owner`, a field read from the untrusted JSON body itself. But the event handlers that actually consume that body identify the target repository/commit using a *different* field (`repository.full_name`, or a bare commit `sha` with no repo scoping at all). In a multi-organization Shipit deployment where at least one configured GitHub App has no `webhook_secret` set, an unauthenticated attacker can pick that low-security organization to satisfy signature verification while pointing the rest of the payload (`repository.full_name`, `sha`, etc.) at a completely different, "secured" repository/stack.

### Finding Description
`verify_signature` resolves the app/org used for HMAC verification purely from the request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved org has no `webhook_secret` configured: [3](#0-2) 

Shipit's own setup docs and secrets templates present `webhook_secret` as optional (`# nil`) per organization in multi-org configurations: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (because it looked at `repository.owner.login` for an app with a blank secret), the full, attacker-controlled `params` hash is dispatched unchanged to every handler for the claimed event: [6](#0-5) 

But the handlers resolve the *actual* target using a different key, `repository.full_name`, with no re-check against the organization/owner used for signature verification: [7](#0-6) [8](#0-7) 

The `StatusHandler` is even less scoped: it matches purely on commit SHA across the entire instance, with no repository check whatsoever: [9](#0-8) 

**Binding broken:** `organization authenticated (repository.owner.login / organization.login, checked against that org's webhook_secret)` ≠ `repository/commit actually written (repository.full_name in PushHandler, bare sha in StatusHandler)`. The engine treats "the signature check passed for organization X" as equivalent to "this payload's `repository`/`sha` claims about organization X's data are trustworthy," which is false the moment more than one GitHub App is configured and any one of them lacks a `webhook_secret`.

### Impact Explanation
An unauthenticated internet attacker who knows (or guesses) the name of any Shipit-configured GitHub organization/App that has no `webhook_secret` set can craft a POST to `/webhooks` with `X-Github-Event: push` (or `status`) where `repository.owner.login` = the unsecured org, but `repository.full_name`/`sha` reference a stack/commit belonging to a *different, secured* organization tracked by the same Shipit instance. This:
- Forces `stack.sync_github` to be triggered for arbitrary tracked stacks (`PushHandler`), and
- Lets the attacker forge/overwrite CI status (`state`, `context`, `target_url`) on **any commit SHA** tracked anywhere in the instance via `StatusHandler`, with zero repository scoping.

Forged CI status directly affects deploy safety gating (`required_statuses`/`blocking_statuses` used by `deploy_spec` and continuous delivery, e.g. `Stack.schedule_continuous_delivery` acting on `continuous_deployment: true` stacks) [10](#0-9) . On stacks with continuous deployment enabled, spoofed "success" statuses can cause an unauthorized automatic deploy — this qualifies as Critical (unauthorized deploy). At minimum this is a High-severity unauthenticated write to stack/commit state that the engine is supposed to gate behind a verified GitHub signature.

### Likelihood Explanation
Any multi-organization Shipit deployment following the project's own documented/templated configuration (`webhook_secret` left blank for one or more orgs) is exposed. No credentials, session, `ApiClient` token, or repository write access are required — only a single unauthenticated HTTP POST to the public `/webhooks` endpoint mounted by the engine, matching the required "unprivileged attacker" and "engine mounted as documented" constraints.

### Recommendation
After signature verification, re-derive the organization/owner strictly from the same field(s) actually used to select/process the target (`repository.full_name`), and reject the request if the verified organization does not match the owner segment of `repository.full_name`. Additionally, scope `StatusHandler` lookups to commits belonging to a stack whose repository owner matches the verified organization, rather than a bare `Commit.where(sha:)` across the whole instance. Consider also requiring `webhook_secret` to be present for every configured GitHub App (fail closed) rather than allowing per-org opt-out of signature verification.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `OrgA` (no `webhook_secret`) and `OrgB` (secured, `webhook_secret` set), both with stacks tracked by this Shipit instance — mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: status` and no/garbage `X-Hub-Signature`, body:
```json
{
  "sha": "<sha of a commit belonging to an OrgB-tracked stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`; since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, regardless of the (missing/invalid) `X-Hub-Signature`.
4. `StatusHandler.process` runs unfiltered against `Commit.where(sha: params.sha)`, applying the forged "success" status to the OrgB commit — with no verification ever performed against OrgB's actual `webhook_secret`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```
