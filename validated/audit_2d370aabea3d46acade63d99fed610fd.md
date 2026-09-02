### Title
Webhook signature is verified against the payload's `repository.owner.login`, but handlers act on the payload's `repository.full_name` — cross-organization forgery of status/push/PR events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from the untrusted request body (`params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1)  Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the repository/stacks to actually mutate using a *different* field of the same untrusted body: `payload.dig('repository', 'full_name')`. [3](#0-2) 

Because Shipit supports multiple GitHub organizations each with its own `webhook_secret` (`config/secrets.yml` keyed per-org, resolved by `Shipit.github(organization:)`), the signature check and the effect-target lookup are bound to two different, independently-attacker-controllable fields of the same JSON body.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `organization whose repository is written by the handler (repository.full_name)`

`verify_signature` never checks this equality — it just trusts whatever `repository.owner.login` (or `organization.login`) says, looks up that org's `GitHubApp`/`webhook_secret`, and verifies the signature against it: [4](#0-3) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```

An attacker who has installed their own GitHub App on their own org (`org-attacker`), and therefore knows `org-attacker`'s `webhook_secret`, can POST directly to the public `/webhooks` endpoint with a body where:
- `repository.owner.login = "org-attacker"` (used only to select the verification secret)
- `repository.full_name = "org-victim/target-repo"` (used by every handler to select the actual `Repository`/`Stack`/`Commit` to act on)

`verify_signature` computes the HMAC against `org-attacker`'s secret (which the attacker controls) and it validates successfully, since the signature is only checked against raw body + secret, with no cross-check that the secret's owner matches `repository.full_name`'s owner.

The handler layer then trusts `repository.full_name` blindly: e.g. `PushHandler` and `Handler#stacks` resolve `Repository.from_github_repo_name(repository_name)` from `payload.dig('repository', 'full_name')` and enqueue a `GithubSyncJob` for the resolved (victim) stack. [5](#0-4)  `StatusHandler` is worse — it doesn't even use `repository.full_name` for scoping; it matches purely by SHA across the whole database (`Commit.where(sha: params.sha)`) and calls `commit.create_status_from_github!(params)` for every match, regardless of repository. [6](#0-5) 

A forged `success` status on a victim's commit feeds directly into `Commit#deployable?` and `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` once the commit looks "deployable" and the stack has continuous deployment enabled: [7](#0-6) [8](#0-7) 

### Impact Explanation
This breaks the deployment-trust binding "organization authenticated == repository/stack written," letting an attacker who legitimately controls only their own org's GitHub App forge webhook events (push, status, pull_request, membership) that are attributed to and acted upon a completely different, victim organization's stacks. In the `StatusHandler` case this can inject a forged passing CI status onto a victim's commit, which can trigger `ContinuousDeliveryJob` and result in an **unauthorized deploy** of a stack the attacker has no access to — matching the Critical bar in scope ("an unauthorized deploy, rollback or merge"). Other handlers (push, pull_request opened/closed/labeled) let the attacker forge sync jobs, archive/unarchive review stacks, or manipulate provisioning state of victim repositories they don't own, an unauthenticated cross-organization write.

### Likelihood Explanation
Likelihood is High for any Shipit deployment that hosts multiple GitHub organizations (explicitly documented and supported via the multi-org `config/secrets.yml` format), since any tenant that legitimately owns/administers their own GitHub App installation automatically possesses everything needed to forge requests against every other tenant's stacks on the same instance — no compromise of the victim's credentials, GitHub session, or infrastructure is required, only a raw HTTP POST to the public `/webhooks` endpoint.

### Recommendation
Enforce that the organization used to select/verify the webhook secret is the same organization the handler will act upon, before any handler runs:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified && repository_owner_matches_target_repository?
end

def repository_owner_matches_target_repository?
  target_owner = params.dig('repository', 'full_name')&.split('/')&.first
  target_owner.blank? || target_owner.casecmp?(repository_owner)
end
```
Additionally, `StatusHandler#process` should scope commits by the verified repository/organization instead of matching by SHA alone across the entire database.

### Proof of Concept
1. Attacker creates/owns `org-attacker` on GitHub, installs the Shipit GitHub App on it, and thus knows `org-attacker`'s `webhook_secret` (a normal, unprivileged self-service action).
2. Attacker crafts a JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/target-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-attacker_webhook_secret, raw_body)` and sends `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` (from `repository.owner.login`), verifies successfully against the attacker's own known secret. [1](#0-0) 
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's commit regardless of repository — and records a forged "success" status on it. [6](#0-5) 
6. If `org-victim/target-repo`'s stack has continuous deployment enabled and this forged status makes the commit `deployable?`, `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, resulting in an unauthorized deploy the attacker never had credentials to trigger. [8](#0-7)

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
