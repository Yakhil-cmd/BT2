### Title
Webhook signature verification selects the signing organization from an unauthenticated payload field that is decoupled from the repository field handlers act on, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository_owner`, a value read directly out of the untrusted, attacker-supplied JSON body. The event handlers, however, resolve the target `Repository`/`Stack` from a *different* JSON field (`repository.full_name`). Because both fields live inside the same attacker-controlled payload and the signature only proves "this body was signed with Org X's secret" (not "this body's target repository belongs to Org X"), a party who legitimately knows one organization's `webhook_secret` can forge a validly-signed webhook that targets a completely different organization's repository/stack.

### Finding Description
In a multi-organization deployment (supported and tested via `test/dummy/config/secrets_double_github_app.yml`), each organization has its own `GitHubApp` config, keyed by organization name, each with its own `webhook_secret`: [1](#0-0) 

`WebhooksController#verify_signature` selects the signing secret via `repository_owner`, which is parsed straight from the JSON body without any independent authentication: [2](#0-1) [3](#0-2) 

Once the signature check passes, `create` dispatches the *entire* raw payload — unfiltered — to event handlers: [4](#0-3) 

Handlers, however, resolve the actual `Repository`/`Stack` to mutate using a *different* payload field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [5](#0-4) 

Nothing binds `repository.owner.login` (used to pick the verifying secret) to `repository.full_name` (used to pick the target stack). An attacker who legitimately possesses the `webhook_secret` for one org configured in Shipit (`OrgA`) can:
1. Craft an arbitrary JSON body with `repository.owner.login = "OrgA"` (so `verify_signature` looks up and validates against `OrgA`'s secret, which the attacker knows) but `repository.full_name = "OrgB/target-repo"` (a repository belonging to a different, unrelated organization also connected to the same Shipit instance).
2. Compute a valid HMAC-SHA1 signature over that exact raw body using `OrgA`'s `webhook_secret`.
3. POST it to `/webhooks` with `X-Github-Event` set to `push`, `status`, or `check_suite`.

`verify_signature` passes (the org-secret lookup succeeds and the HMAC matches), and the handler then acts on `OrgB`'s stack:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for any not-archived stack on the matching branch of `OrgB/target-repo`: [6](#0-5) 
- `StatusHandler#process` creates a forged commit status (`commit.create_status_from_github!`) on any existing commit whose `sha` matches, independent of repository at all — status lookup is purely by commit SHA: [7](#0-6) 
- `CheckSuiteHandler#process` schedules a check-run refresh for `OrgB`'s commits: [8](#0-7) 

This is the same bug class as the reported precision-loss issue: a trust decision (which secret authenticates the payload) is made on a field (`repository.owner.login`) that is never actually bound/reconciled with the field the privileged action is executed against (`repository.full_name`). Just as `Scaler.scale()` derives voting power from a decimal parameter divorced from the real economic stake, `verify_signature` derives cryptographic trust from an org-owner field divorced from the actual repository the handler mutates.

### Impact Explanation
This breaks the equality that should hold: `organization-that-authenticated == organization-owning-the-repository-being-written`. Concretely it can be leveraged to forge fake commit statuses (`StatusHandler`) that can satisfy Shipit's deployability checks or trigger an out-of-band `GithubSyncJob`/deploy (`PushHandler`) for a target stack the attacker does not control, i.e. an unauthorized deploy/rollback trigger through a cross-organization forged webhook. This matches the Critical impact criterion "cross-repository writes[...] or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitability requires the attacker to legitimately hold the `webhook_secret` for *some* organization already onboarded to the same multi-tenant Shipit instance — a realistic scenario in the documented/tested multi-org ("double GitHub App") configuration where different organizations' admins each configure and know their own app's webhook secret, yet all events funnel through the same `/webhooks` endpoint and shared handler dispatch. No GitHub App private key, session, or Shipit API token is required — only knowledge of one valid `webhook_secret` in the deployment.

### Recommendation
After `verify_signature` succeeds, re-derive the organization owning the *actual* target repository (`repository.full_name`) independently (e.g., via `Repository.from_github_repo_name` → its configured install/org) and require it to match the organization whose secret validated the signature. Reject the webhook (422) if they diverge, instead of trusting `repository.owner.login` as an unchecked routing hint.

### Proof of Concept
1. Configure Shipit with two orgs (`OrgA`, `OrgB`), each with a distinct `webhook_secret`, mirroring `test/dummy/config/secrets_double_github_app.yml`. `OrgB` owns repository `OrgB/target-repo`, tracked as a Shipit `Stack`.
2. As an attacker who administers `OrgA`'s GitHub App (and thus knows `OrgA`'s `webhook_secret`), build a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `sha1=<hmac>` using `OrgA`'s `webhook_secret` over the exact raw body.
4. `POST /webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<hmac>`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully (attacker knows the secret), and `PushHandler` calls `sync_github` on `OrgB/target-repo`'s stack — a repository the attacker's org never owned or was authorized to affect.

### Citations

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
