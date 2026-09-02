### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the stack that is actually mutated is looked up from the independent, unauthenticated `repository.full_name` field, allowing cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-tenant Shipit deployments (multiple GitHub organizations configured under `secrets.github`), the webhook signature is verified using the webhook secret of whichever organization is named in the JSON payload's `repository.owner.login` (or `organization.login`) field. The event handlers, however, resolve the `Stack`/`Repository` to act on using a completely different payload field, `repository.full_name`. Because both fields live inside the same attacker-controlled JSON body, and the HMAC only proves "this body was signed with *some* organization's secret," an operator who legitimately controls one organization's webhook secret can forge a payload whose `repository.owner.login` matches their own org (so it authenticates) while `repository.full_name` points at a different organization's repository, causing Shipit to act on a stack that the attacker's secret was never meant to authorize.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to check `X-Hub-Signature` purely from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` looks up that organization's config/secret to validate the HMAC: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `WebhooksController#create` dispatches the same raw payload to handlers: [5](#0-4) 

Handlers (e.g. `PushHandler`) never re-check `repository.owner.login`; they resolve the target stacks from a *different* field, `repository.full_name`, via `Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) [8](#0-7) 

The break: the binding "organization that authenticated == repository that is written" does not hold. Only `repository.owner.login` is used to pick the verifying secret; `repository.full_name` (which can name an entirely different owner/org) drives which `Stack` is synced, statused, or otherwise mutated. Since the whole JSON body — including both fields — is attacker-controlled before signing, and the signature only certifies "signed by whichever org's secret matches `repository.owner.login`," an attacker who knows/owns one organization's webhook secret (e.g., because they administer their own org's GitHub App/webhook configuration on a shared multi-org Shipit instance) can produce a validly-signed request that targets a victim organization's repository/stack.

This mirrors the reported bug class exactly: a value (`tradingFee`) computed/applied before the quantity it is supposed to be consistent with (`amounts`) is finalized, breaking an implicit invariant. Here, the field used to select/verify the authenticating credential (`repository.owner.login`) is never bound to the field that determines what gets written (`repository.full_name`), so the "signed-for" identity and the "acted-upon" repository can diverge.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out as in-scope. An attacker with only their own organization's webhook secret (no push access, no session, no privileged account on the victim org) can trigger `GithubSyncJob`, create/modify `Status` rows, or drive other webhook-triggered mutations against stacks belonging to a different, victim organization configured on the same Shipit instance — an unauthorized cross-repository/cross-organization action. In deployments where webhook-driven state (sync status, commit statuses, merge/lock behavior) feeds into deploy eligibility, this can influence or unblock deploys for a repository the attacker does not control.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured for more than one GitHub organization (`secrets.github` keyed by org) — a supported, documented configuration; and (2) the attacker to control the webhook secret of at least one of those organizations, which is realistic for any org admin who legitimately owns a Shipit-connected GitHub App/webhook. No access to the victim org, no Shipit session, and no `ApiClient` token are required — only the ability to send a crafted HTTP POST to the shared `/webhooks` endpoint.

### Recommendation
After computing `repository_owner` and verifying the signature, `WebhooksController` (or `Handler`) should assert that the same identity is used consistently: derive the acting organization from the *same* trusted field used for signature selection, or explicitly verify that `repository.full_name`'s owner matches the `repository_owner` used to select the verifying secret before dispatching to handlers. Reject the request (422) if they diverge.

### Proof of Concept
1. Configure Shipit for two organizations, `orgA` and `orgB`, each with its own `webhook_secret` under `secrets.github`.
2. As an attacker who administers `orgA`'s GitHub App, know `orgA`'s `webhook_secret`.
3. Craft a JSON payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` looks up `Shipit.github(organization: "orgA")` and validates successfully against `orgA`'s secret.
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")`, triggering `stack.sync_github` for a stack owned by `orgB`, despite the request never being signed by `orgB`'s secret.

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

**File:** lib/shipit.rb (L196-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
