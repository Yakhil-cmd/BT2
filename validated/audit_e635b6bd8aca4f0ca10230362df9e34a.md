### Title
Webhook signature-verification target diverges from the repository the handler acts on, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate a delivery against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Every downstream `Handler` (e.g. `PushHandler`, `CheckSuiteHandler`) instead resolves the *acted-upon* repository from a separate, independently-controlled JSON field: `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing ties these two lookups together, so the organization whose secret authenticated the request is not guaranteed to be the owner of the repository the handler subsequently mutates.

### Finding Description
`verify_signature` chooses the trust boundary like this: [2](#0-1) [3](#0-2) 

The comment "Fallback to the organization sub-object if repository isn't included in the payload" shows the code intentionally accepts either the `repository.owner.login` or the wholly separate `organization.login` field to pick the app whose HMAC secret is checked, via `Shipit.github(organization: repository_owner)` [4](#0-3) .

Once the signature passes, the raw JSON is dispatched unchanged to the event handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . Handlers derive the actual repository/stack to mutate purely from `repository.full_name`, never from `repository.owner.login` or `organization.login`: [1](#0-0) 

`PushHandler` then triggers a GitHub sync for every non-archived stack on that repository matching the branch: [6](#0-5) ; `CheckSuiteHandler` schedules check-run refreshes for commits on that repository's stacks: [7](#0-6) .

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository_owner)` == `repository written by the handler (repository.full_name owner)`

In a multi-organization Shipit deployment, each org has its own independently configured `app_id` / `installation_id` / `webhook_secret` in `secrets.yml`, set up by whoever created that org's GitHub App [8](#0-7) . An org admin who legitimately knows their own org's `webhook_secret` (they created/configured it) can sign an arbitrary raw POST body to the shared `/webhooks` endpoint. By setting `repository.owner.login`/`organization.login` to their own org (or omitting `repository.owner` and relying on the `organization.login` fallback) while setting `repository.full_name` to `victim-org/some-repo`, the request passes signature verification against their own org's secret, but the handler acts on the victim organization's repository/stack.

### Impact Explanation
This crosses an organizational trust boundary that Shipit's multi-tenant model assumes is isolated: an attacker who legitimately controls one org's webhook secret can trigger `GithubSyncJob` (`PushHandler`), forge commit statuses for the victim repo's commits (`StatusHandler` matches purely on `sha` globally, not scoped to owner at all), and schedule check-run refresh jobs (`CheckSuiteHandler`) against a stack belonging to an organization they do not control. This is a cross-repository/cross-organization action performed under another org's stacks without authorization — matching the "cross-repository writes" / "unauthorized deploy" impact class, since a forced sync or fabricated commit status can influence whether a victim's stack is considered deployable and can feed into automated deploy/merge decisions.

### Likelihood Explanation
Requires the attacker to already administer at least one organization/GitHub-App instance configured in this shared Shipit deployment (i.e., know that org's own `webhook_secret`, which they set up themselves) — this is a lower bar than compromising the victim's secret, an `ApiClient` token, or a privileged Shipit account. This scenario is realistic specifically for the documented "Using Multiple GitHub Applications" configuration [8](#0-7) , where distinct, mutually-untrusted organizations share one Shipit instance and each configures its own app secret.

### Recommendation
Bind the field used for signature/app selection to the same field the handlers act on. Concretely, `WebhooksController#repository_owner` should derive the app strictly from `repository.full_name`'s owner segment (or otherwise validate that `repository.owner.login`/`organization.login` matches the owner portion of `repository.full_name`) before dispatching to handlers, and reject requests where these fields disagree.

### Proof of Concept
1. Deployment configures two orgs, `attacker-org` and `victim-org`, each with its own GitHub App (`webhook_secret`s `SECRET_A` and `SECRET_V` respectively), per the documented multi-org config [8](#0-7) .
2. Attacker, an admin of `attacker-org`'s GitHub App, knows `SECRET_A`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "victim-org/private-repo" },
  "organization": { "login": "attacker-org" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(SECRET_A, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` → `"attacker-org"` (since `repository.owner` is absent) [3](#0-2) , fetches `Shipit.github(organization: "attacker-org")`, and validates successfully against `SECRET_A`.
6. `create` dispatches the payload to `PushHandler`, which resolves `repository_name = "victim-org/private-repo"` [9](#0-8)  and calls `stack.sync_github(expected_head_sha: ...)` on `victim-org`'s stacks [6](#0-5)  — an action authenticated under `attacker-org`'s credentials but executed against `victim-org`'s repository.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
