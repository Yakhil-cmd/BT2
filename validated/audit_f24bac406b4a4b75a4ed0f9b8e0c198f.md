### Title
Webhook signature verification authenticates `repository.owner.login` while event handlers act on the untrusted `repository.full_name`, allowing cross-organization webhook forgery in multi-tenant deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a payload against using `repository.owner.login` (or `organization.login`), but every webhook `Handler` subsequently resolves the target `Stack`/`Repository` using the completely independent `repository.full_name` field from the same, attacker-controlled JSON body. Nothing ties these two fields together, so a valid signature computed with one organization's secret can be replayed with a forged `full_name` pointing at another organization's repository in the same multi-tenant Shipit instance.

### Finding Description
`before_action :verify_signature` in the webhooks controller picks the `GitHubApp` config to check the signature against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the unauthenticated, unverified raw request body (`params.dig('repository', 'owner', 'login')`), before the signature has been checked. `Shipit.github(organization: repository_owner)` then looks up that organization's own dedicated config/secret: [3](#0-2) 

This multi-organization mode, where each org has its own independent `webhook_secret`, is a documented, supported deployment configuration: [4](#0-3) 

Once `verify_webhook_signature` succeeds (HMAC computed over the *entire* raw body using the org's secret), `WebhooksController#create` dispatches the **same raw payload** to the event handlers: [5](#0-4) 

Every handler, however, resolves the affected repository/stack using a *different* field of the payload, `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

For example `PushHandler` uses this to find stacks and immediately triggers a GitHub sync with an attacker-supplied `after` SHA: [7](#0-6) 

Because a legitimate GitHub-generated payload always keeps `repository.owner.login` consistent with `repository.full_name`, this equality is silently assumed but never enforced by Shipit. An attacker who controls (or is the legitimate GitHub App admin of) one organization "OrgA" hosted on the same multi-tenant Shipit instance knows OrgA's `webhook_secret` (they configured/received it when the App was created for their org). They can craft a POST to `/github/webhooks` with:
- `X-Hub-Signature` = HMAC-SHA1(OrgA's `webhook_secret`, raw_body)
- `repository.owner.login = "OrgA"` (so `verify_signature` selects and successfully validates against OrgA's secret)
- `repository.full_name = "OrgB/target-repo"` (a repository belonging to a different, unrelated tenant/organization "OrgB" also served by the instance)

`verify_signature` passes because the signature is valid for OrgA's secret over that exact body. `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` then runs `PushHandler`, which resolves `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` for a stack the attacker has no legitimate relationship to. The equality that should hold — "organization whose secret authenticated the request" == "repository the request is permitted to act on" — is broken.

### Impact Explanation
This crosses a repository/organization trust boundary explicitly called out as Critical: an attacker with legitimate credentials scoped to one tenant organization can forge webhook events (push, pull_request, membership, status, check_suite, etc.) that are processed as if they originated from a completely different tenant's repository, enabling cross-repository writes/state changes (e.g., forcing a `GithubSyncJob` with an attacker-chosen `expected_head_sha`, archiving/unarchiving review stacks, injecting commit statuses) on stacks belonging to organizations the attacker does not control — all without ever obtaining that target organization's `webhook_secret`, an `ApiClient` token, or repository write access on the victim repo.

### Likelihood Explanation
Exploitation only requires: (1) the instance operator runs the documented multi-org github config (a normal, intended deployment mode, not a misconfiguration), and (2) the attacker controls the `webhook_secret` of any one of the configured organizations (which is the expected level of trust/knowledge for an org onboarded onto the shared Shipit instance). No access to the victim organization's repository, GitHub App, or Shipit session/API token is required, and no code currently cross-checks `repository.owner.login` against `repository.full_name`.

### Recommendation
After signature verification, re-validate that the organization used to select the verifying secret matches the owner segment of `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers, and reject the request otherwise. Alternatively, scope the `Repository`/`Stack` lookup performed by each `Handler` to only repositories known to belong to the verified organization.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the administrator/attacker of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), build a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POST it to `/github/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and invokes `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` for `OrgB`'s stack, despite the request never being signed by `OrgB`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
