### Title
Webhook signature verified against attacker-controlled `repository.owner.login` while write actions target `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) taken directly from the untrusted request body, while every webhook `Handler` resolves the target `Stack`/`Repository` using a different field from the same body, `repository.full_name`. Because Shipit supports multiple organizations each configured with its own GitHub App and `webhook_secret`, an attacker who legitimately controls one configured organization's webhook secret can forge a payload whose `owner.login` matches their own org (so the signature check passes) but whose `full_name` names a repository belonging to a different, victim organization.

### Finding Description
`verify_signature` computes the verifying organization from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the `GitHubApp` instance (and thus the `webhook_secret`) keyed by that organization, as configured per-org in secrets (multiple orgs each with independent webhook secrets is a documented, supported configuration): [3](#0-2) 

`GitHubApp#verify_webhook_signature` only checks the HMAC against that organization's own secret: [4](#0-3) 

Once the signature is accepted, `WebhooksController#create` dispatches the parsed JSON to handlers: [5](#0-4) 

But every handler resolves the repository to act on from `repository.full_name`, a field that was never part of the value the signature check keyed off of (`owner.login`): [6](#0-5) 

For example `PushHandler` (and `StatusHandler`, `CheckSuiteHandler`, etc.) uses `stacks` derived from that `full_name` lookup to trigger `sync_github`, create commit statuses, etc.: [7](#0-6) [8](#0-7) 

`Repository.from_github_repo_name` performs a straight lookup on `owner/name` parsed from `full_name`, with no cross-check against `repository.owner.login`: [9](#0-8) 

The equality that should hold is: `organization authenticated by the webhook signature (repository.owner.login) == organization whose repository/stack state is mutated (repository.full_name's owner)`. The code never enforces this equality — an attacker who legitimately administers "orgB" (and therefore knows/controls orgB's own `webhook_secret`, since they can configure their own GitHub App on their own org) can send a request to the shared `/webhooks` endpoint with `repository.owner.login = "orgB"` (making `verify_signature` pass using orgB's secret) but `repository.full_name = "orgA/victim-repo"`, causing handlers to mutate state belonging to org A, which the attacker never authenticated for.

### Impact Explanation
This allows an attacker who owns/administers one Shipit-configured organization to forge webhook events that are processed as if they came from GitHub for a different organization's repository. Depending on handler, this can:
- Force `sync_github` on a victim stack (`PushHandler`), and inject `Commit`/`Status` records via `StatusHandler`, potentially manipulating `deployable_status` and CI gating used to permit deploys.
- Create teams/users via `MembershipHandler`.

Because `deployable_status`/commit status data influences whether a stack is considered deployable, forged status events for a victim's commits could be used to unlock or otherwise influence deploy eligibility, meeting the "unauthorized deploy" bar defined for this engine. This crosses an organization trust boundary without any GitHub-side authentication for the target org, which is the same "front-run/misbound identity" class as the reported finding: a value that is checked (owner used for signature) is not the same value that is acted upon (full_name used for state mutation).

### Likelihood Explanation
Requires the attacker to control a legitimately configured Shipit organization/webhook secret (i.e., not a completely anonymous outsider), which is a lower bar than repository write access or an `ApiClient` token for the target org — it only requires being an admin of some other org that the same Shipit instance also serves. Multi-org Shipit deployments are explicitly supported and documented, so this is a realistic deployment shape, not a hypothetical misconfiguration.

### Recommendation
After signature verification, additionally validate that `repository.full_name`'s owner matches `repository.owner.login` (or `organization.login`) used to select/verify the webhook secret, rejecting the webhook if they diverge. Alternatively, scope the found `Repository`/`Stack` lookup to also require it belongs to the same organization key that verified the signature.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with a distinct GitHub App and `webhook_secret` (as shown in `config/secrets.development.shopify.yml`).
2. As the attacker controlling `orgB`'s own GitHub App, craft a `push` (or `status`) webhook JSON body:
```json
{
  "repository": { "full_name": "orgA/victim-repo", "owner": { "login": "orgB" } },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. Compute `X-Hub-Signature` using `orgB`'s known `webhook_secret` over this exact raw body, per `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` semantics.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgB"`, fetches `orgB`'s `webhook_secret`, and the signature verifies successfully.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgA/victim-repo")`, which belongs to `orgA`, and triggers `sync_github` on the victim's stack — even though the attacker never authenticated against `orgA`.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
