This confirms the vulnerability: the trust binding used for signature verification (`repository.owner.login`) is decoupled from the trust binding used to select which `Stack`/`Repository` the event actually writes to (`repository.full_name`).

### Title
Webhook signature verification is keyed off an unverified `repository.owner.login` field that is decoupled from the `repository.full_name` used to select the affected Stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted, unparsed JSON body, before the signature has been checked. [1](#0-0)  The event handlers, however, determine which `Repository`/`Stack` the event actually mutates using a *different* field from the same untrusted payload: `repository.full_name`. [2](#0-1)  Because these two fields are independently attacker-controlled inside a single JSON body, the organization whose secret "authenticates" the request is not bound to the repository that is actually written to.

### Finding Description
`repository_owner` is computed purely from `params` (the parsed but unverified JSON body):
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

This value is used to look up which multi-org GitHub App config (and hence which `webhook_secret`) verifies the signature:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
``` [4](#0-3) 

`GitHubApp#verify_webhook_signature` explicitly returns `true` — bypassing HMAC entirely — whenever no `webhook_secret` is configured for that organization:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [5](#0-4) 

Once the request passes this check, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to the concrete handlers, all of which resolve the target `Stack` using an entirely different key of the same payload — `repository.full_name` — not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

Handlers such as `PushHandler` (triggers `stack.sync_github`, i.e. a `GithubSyncJob`) and `StatusHandler` (writes commit statuses) operate purely on the `stacks`/`Commit.where(sha:)` resolved from `repository.full_name`. [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization whose secret authenticated the request == owner of the repository that the handler actually mutates`

In a multi-organization Shipit deployment (the "multi org" config schema explicitly supported by `Shipit.github_app_config`) [8](#0-7) , if *any* configured organization omits `webhook_secret` (documented as optional in the setup guide) [9](#0-8) , an unprivileged attacker can send a POST to `/webhooks` with:
- `repository.owner.login` = that no-secret organization (satisfies `verify_signature`, which unconditionally returns `true` for it), and
- `repository.full_name` = `victim-org/victim-repo` (any repository actually tracked by the Shipit instance, in a *different* organization).

Because the two fields are read independently from the same attacker-supplied JSON, the signature check is fully satisfied while the mutated repository is under the attacker's control and unrelated to the "authenticated" organization.

### Impact Explanation
This breaks the deployment-trust binding between "organization that authenticated" and "repository that is written," matching the High-impact class of "unauthenticated read of stack state" and edges toward unauthorized deploy triggering: a forged `push` event can trigger `GithubSyncJob`/`stack.sync_github` for a legitimate stack, and a forged `status`/`check_suite` event can write fabricated commit statuses/check-run results (`Commit#create_status_from_github!`) that downstream CI-gating and merge-queue logic rely on to permit deploys/merges. This can be leveraged to make a stack believe CI has passed when it has not, an unauthorized-deploy-adjacent effect through webhook forgery rather than through the GitHub API/CI itself.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it requires (a) multi-org GitHub App configuration, and (b) at least one configured organization without a `webhook_secret`. Both conditions are explicitly supported/documented as valid ("Webhook secret (optional)") [9](#0-8) , so this is a realistic, not purely theoretical, misconfiguration that the engine's own code permits rather than something the host app must avoid deviating from documented behavior to hit.

### Recommendation
Do not let the attacker-controlled payload decide which secret verifies the payload and which repository the handler acts on independently. Either:
1. Require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), or
2. After computing the verified organization, cross-check that `repository.full_name`'s owner segment matches the organization whose secret verified the signature before dispatching to handlers, rejecting mismatches with `422`.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `org-a` (no `webhook_secret`) and `org-b` (tracked stack `org-b/victim-repo`, `webhook_secret` set).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already merged in victim repo>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
No valid `X-Hub-Signature` for `org-b` is required, since `repository_owner` resolves to `org-a`, whose `GitHubApp#verify_webhook_signature` short-circuits to `true` per [10](#0-9) .
3. `verify_signature` passes; `PushHandler` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)`, causing `org-b`'s stack to sync/enqueue against an attacker-chosen SHA. [6](#0-5)

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
