Confirmed: `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) resolves the target purely from `repository.full_name`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) acts on whatever `stacks` that resolves to — a field completely independent of `repository_owner` used for signature selection in `WebhooksController#verify_signature`.

### Title
Cross-organization webhook forgery via organization/repository field mismatch in signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using `repository_owner`, a value read from `payload.dig('repository','owner','login')` (or `organization.login`). However, every webhook `Handler` (e.g. `PushHandler`, `PullRequest::OpenedHandler`, `LabelCapturingHandler`) resolves the actual `Repository`/`Stack` to mutate from a *different* payload field, `repository.full_name`, via `Repository.from_github_repo_name`. These two fields are never cross-checked against each other, so a signature that is valid (or trivially bypassed) for organization A can be used to forge and process events against organization B's repositories.

### Finding Description
`Shipit.github(organization: repository_owner)` in `lib/shipit.rb:170-181` looks up the `GitHubApp`/secret for whichever organization key matches `repository_owner`. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) explicitly returns `true` when that organization's `webhook_secret` is blank: [1](#0-0) 
`webhook_secret` being left blank is a documented, supported configuration (`docs/setup.md:119`, `config/secrets.development.example.yml:11`, and the multi-org example `docs/setup.md:194`), so it is realistic for at least one onboarded organization in a multi-app setup to have no secret configured while other organizations do.

The controller only uses `repository_owner` to pick which secret is checked: [2](#0-1) [3](#0-2) 

Once `verify_signature` passes, `create` dispatches the *entire* raw payload to the registered handlers unmodified: [4](#0-3) 

Every handler, however, determines which `Repository`/`Stack` to act on from `repository.full_name`, not from `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

Because `repository.owner.login`/`organization.login` (verification key) and `repository.full_name` (action target) are independent, attacker-controlled JSON fields inside the same request body, there is nothing enforcing that the organization whose secret validated the request is the same organization whose repository gets acted upon. This is the same class of bug as the reported `transferFrom`/`transfer` mismatch: the check is performed against one binding (`repository_owner` ⇄ secret) while the effect is applied to a different binding (`repository.full_name` ⇄ mutated Stack/Repository), and the two are never asserted equal.

### Impact Explanation
An attacker who knows (or guesses) the name of any organization configured on the Shipit instance with a blank `webhook_secret` — a supported, documented configuration — can craft a webhook body where `repository.owner.login`/`organization.login` is set to that low-value organization (so verification trivially passes) while `repository.full_name` names a *different*, properly protected organization's repository. This forged, unsigned-in-practice payload is then processed against the victim organization's stacks, allowing:
- Forged `push` events (`PushHandler`) to trigger `Stack#sync_github` / `GithubSyncJob` with an attacker-chosen `after` SHA on arbitrary stacks, which can drive continuous-deployment pipelines.
- Forged `pull_request` events to auto-provision (`OpenedHandler`), archive (`ClosedHandler`), or unarchive (`ReopenedHandler`) review stacks belonging to a victim org/repo.
- Forged `pull_request` label events (`LabelCapturingHandler`) to inject labels controlling review-app provisioning behavior for the victim's repositories.

This crosses the organization/repository authentication boundary the webhook verification is meant to enforce, resulting in unauthorized cross-repository writes and can drive an unauthorized deploy — matching the Critical/High impact classes defined in scope.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with the documented multi-GitHub-App schema, and (2) at least one onboarded organization with a blank `webhook_secret` — both are explicitly presented as supported/normal configurations in `docs/setup.md` and the shipped example secrets files, so this is a realistic, not contrived, deployment. No session cookie, ApiClient token, or knowledge of any org's actual secret is required; the attacker only needs to know the name of one weakly-configured organization.

### Recommendation
Bind the field used for signature verification to the field used for processing: after selecting the `GitHubApp`/secret via `repository_owner`, verify that `payload.dig('repository','full_name')` actually belongs to that same organization (case-insensitive prefix match on `"#{repository_owner}/"`) before dispatching to handlers, and reject the request otherwise. Additionally, disallow (or warn loudly on) a blank `webhook_secret` for any but the single/default-organization configuration, since a blank secret undermines the multi-org isolation model entirely.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgWeak` (no `webhook_secret`) and `OrgTarget` (has `webhook_secret` set and manages a private `OrgTarget/prod` repo/stack with `continuous_deployment: true`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no (or garbage) `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-already-merged-upstream>",
  "repository": { "owner": { "login": "OrgWeak" }, "full_name": "OrgTarget/prod" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgWeak")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) signature header.
4. `PushHandler#process` resolves the target via `repository.full_name` = `"OrgTarget/prod"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `OrgTarget`'s stack — an action that should have required a signature validated with `OrgTarget`'s secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
