### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the handler acts on the unrelated `repository.full_name` field from the same unverified binding, allowing cross-organization/cross-repository forgery in multi-app deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When Shipit is configured with multiple GitHub Apps (one per organization, per the documented "Using Multiple Github Applications" setup), `WebhooksController#verify_signature` picks *which organization's* `webhook_secret` to validate the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, not-yet-verified JSON body. [1](#0-0) [2](#0-1)  Once the signature check passes, the actual event `Handler` looks up the target `Stack`/`Repository` using a *different* field from that same body — `repository.full_name` — with no check that it belongs to the organization whose secret was used to authenticate the request. [3](#0-2) 

### Finding Description
The binding that should hold is: `organization whose webhook_secret authenticated the request == organization owning the repository the handler writes to`. The code breaks this equality because two independent fields of the same attacker-suppliable payload are used for two different trust decisions, and they are never cross-validated:

- `verify_signature` selects the `GitHubApp` (and thus the `webhook_secret` used in the HMAC comparison) using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` of the raw, not-yet-authenticated body. [1](#0-0) [2](#0-1)  `Shipit.github(organization:)` maps this string to a specific `GitHubApp` config/secret. [4](#0-3) 
- After the HMAC check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same parsed body to handlers such as `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`. [5](#0-4) 
- Every handler resolves the target repository via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a field completely independent from the `owner.login` used for signature-org selection — and uses it to find the `Stack`(s) to act on. [3](#0-2) 

Because an attacker who legitimately controls one configured organization (e.g., they administer OrgA's GitHub App and know/can trigger OrgA's real `webhook_secret`-signed deliveries) can freely choose the JSON body's `repository.full_name`, they can set `repository.owner.login = "orga"` (so the signature check validates against OrgA's secret, which they can satisfy) while setting `repository.full_name = "orgb/victim-repo"` (a stack belonging to a completely different, unrelated organization configured on the same Shipit instance). Nothing in `WebhooksController` or `Handler` enforces that the `full_name`'s owner matches the `owner.login` used to select the verifying secret.

### Impact Explanation
This is a direct analog of the M-2 report's pattern: a field that is *acted upon* (here, `repository.full_name`, driving which `Stack`/`Repository` gets written to) is never actually covered/bound by the trust check that was performed (here, the HMAC signature keyed to `repository.owner.login`). The result is cross-repository/cross-organization writes: `PushHandler#process` can trigger `stack.sync_github` on a victim org's stack, `StatusHandler#process` can inject/forge commit statuses via `commit.create_status_from_github!` for commits on a victim's stack, and `CheckSuiteHandler`/`MembershipHandler` can similarly act on state that should be exclusively controlled by the victim organization's own GitHub App deliveries — all without ever possessing the victim organization's `webhook_secret`. This matches the "cross-repository writes" / "unauthorized deploy" impact bar, since forged push/status events feed directly into `sync_github` and deployability computations that gate deploys.

### Likelihood Explanation
This only manifests on Shipit installations using the documented multi-organization GitHub App configuration (`github_organizations` / per-org `webhook_secret` keys), which is a supported, documented deployment mode, not a misconfiguration. Any actor who controls (or can get signed deliveries from) at least one configured organization's GitHub App — an "unprivileged" position relative to the *other* organizations hosted on the same Shipit instance — can exploit this without ever touching the victim org's secret.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner`/`organization` from the same field used to select the verifying secret, and require every downstream handler's `repository_name`/`full_name` lookup to belong to that same verified organization before acting (e.g., reject or `head(422)` if `repository.full_name.split('/').first` doesn't case-insensitively match the organization whose `webhook_secret` validated the signature).

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section).
2. As the operator/holder of OrgA's GitHub App webhook secret, craft a `push` (or `status`) webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature` using OrgA's real `webhook_secret` over the raw body — this is a signature the attacker can legitimately produce.
4. POST to `/webhooks` with header `X-Github-Event: push`. `verify_signature` resolves `repository_owner` = `"orga"`, fetches OrgA's `GitHubApp`, and the HMAC check passes. [1](#0-0) 
5. `PushHandler#process` runs `Repository.from_github_repo_name("orgb/victim-repo")` via `Handler#repository_name`/`#stacks` and triggers `stack.sync_github` on OrgB's victim stack — a write the attacker never had OrgB's credentials to authorize. [6](#0-5) [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
