### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but stack-mutating handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` to validate the HMAC signature using `repository.owner.login` (or `organization.login`) from the JSON payload, but every default webhook handler (`Handler#repository_name`, used transitively by `PushHandler`, the `PullRequest::*` handlers, etc.) resolves the target `Stack`/`Repository` using the **different** field `repository.full_name`. Nothing ties these two fields together, so a signature that is valid for one organization's webhook secret can carry a `repository.full_name` pointing at a completely different organization's stack.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The organization used to select the correct `webhook_secret` (via `Shipit.github(organization: ...)`, see `lib/shipit/github_app.rb` `verify_webhook_signature`) is `repository.owner.login`. [2](#0-1) 

Once the signature check passes, `create` dispatches the raw JSON `params` unmodified to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Every default handler (`PushHandler`, and the `PullRequest::*` handlers) resolves which `Stack`/`Repository` to mutate using `Handler#repository_name`/`repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler#process` then directly triggers a GitHub sync (`sync_github`) for whichever stacks match that `full_name`: [5](#0-4) 

Since GitHub Apps allow a webhook secret per organization/installation (Shipit's own docs describe multi-organization configuration in `config/secrets.development.shopify.yml`), an attacker who legitimately controls (or has installed the Shipit GitHub App for) organization A knows organization A's `webhook_secret`. That attacker can send a POST to `/webhooks` with:
- `repository.owner.login = "org-a"` (so `verify_signature` selects org A's secret, which the attacker knows and can therefore forge a valid `X-Hub-Signature` for the whole raw body),
- `repository.full_name = "org-b/victim-repo"` (an entirely different, unrelated repository/stack tracked by the same Shipit instance).

`repository_owner` (used for the trust decision) and `repository_name`/`full_name` (used for the write action) are two unrelated fields of the same attacker-controlled JSON body; the equality `repository.owner.login == repository.full_name.split('/').first` is never enforced anywhere in the controller or in `Handler`.

### Impact Explanation
This breaks the binding "organization that authenticated versus the repository that is written." A tenant that only controls one organization's webhook secret can forge webhook events (`push`, `pull_request` open/close/reopen/label, etc.) that are dispatched against another organization's stack that happens to be hosted on the same shared Shipit instance. Concretely, this can:
- Force a spurious `GithubSyncJob`/`sync_github` for a victim stack, triggering re-fetch of "new" commits and — because of continuous deployment — potentially triggering unauthorized deploys of a victim repository's stack (`PushHandler#process` → `stack.sync_github`, which is the trigger used elsewhere to queue deploys). [5](#0-4) 
- Archive/unarchive review stacks, or mutate PR-linked stacks belonging to a victim organization via the `PullRequest::*` handlers, all of which key off `repository.full_name` alone (e.g. `ClosedHandler#repository`, `OpenedHandler#repository`). [6](#0-5) [7](#0-6) 

This qualifies as a cross-repository write / unauthorized deploy trigger under the engine's own webhook-authentication boundary, matching the "Critical" bucket (cross-repository writes / unauthorized deploy or rollback).

### Likelihood Explanation
Exploitability requires only that the attacker be an onboarded tenant of the same multi-org Shipit deployment (i.e., they administer their own GitHub App/organization webhook secret) — no Shipit session, `ApiClient` token, or repository write access to the *victim* repo is needed. This is a realistic configuration since Shipit explicitly documents supporting multiple GitHub organizations sharing one instance (`config/secrets.development.shopify.yml`). [8](#0-7) 

### Recommendation
After verifying the HMAC signature, cross-check that `repository.owner.login` (the identity the signature was verified against) matches the owner segment of `repository.full_name` (or `organization.login` for org-scoped events) before dispatching to handlers. Reject the webhook (422) if they diverge. Alternatively, have `Handler#repository_name`/`stacks` derive the repository strictly from the same verified organization identity rather than trusting an independent `full_name` field pulled from the unauthenticated-until-that-point JSON body.

### Proof of Concept
1. Attacker operates GitHub organization `org-a`, which is installed as a tenant on the shared Shipit instance, and knows `org-a`'s configured `webhook_secret`.
2. Victim organization `org-b` also has a stack tracked on the same Shipit instance (e.g. `org-b/victim-repo` on branch `main`).
3. Attacker crafts a `push` event payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<any-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a-webhook-secret, raw_body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully because the attacker used `org-a`'s real secret over the exact raw body. [9](#0-8) 
6. `create` forwards the parsed payload to `PushHandler`, which resolves stacks via `repository.full_name == "org-b/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an action the attacker had no authorization to trigger. [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
