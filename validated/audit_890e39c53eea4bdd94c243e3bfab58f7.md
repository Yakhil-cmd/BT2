### Title
Webhook Signature Verification Binds to the Wrong Organization, Allowing Cross-Organization Forged Webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit's webhook endpoint verifies the HMAC signature of an inbound webhook using a `webhook_secret` selected by the `repository.owner.login` (or `organization.login`) field of the JSON body, but the handlers that actually mutate state (create commits, update statuses, sync repositories, etc.) select the target `Repository`/`Stack` using a *different* field of the same body: `repository.full_name`. These two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and the "repository the request is allowed to write to" are two independently attacker-controlled values.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to verify against solely based on `repository_owner`: [1](#0-0) 

with `repository_owner` computed from the raw JSON body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves to a possibly org-specific `GithubApp` configuration (each org can have its own `webhook_secret`, as shown by the multi-app fixture `test/dummy/config/secrets_double_github_app.yml`), and `verify_webhook_signature` performs a straightforward HMAC-SHA1 comparison over the raw body using that org's secret: [3](#0-2) 

Once the signature check passes, the full `params` (the same JSON body, unmodified) is dispatched to handlers: [4](#0-3) 

Every handler resolves the actual `Repository`/`Stack` to act on from a **different** field of that same body — `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

`Repository.from_github_repo_name` then does a simple owner/name lookup with no relation to which secret validated the request: [6](#0-5) 

Because the signature check is keyed on `repository.owner.login`/`organization.login` while every downstream mutation is keyed on `repository.full_name`, nothing in the code enforces:

`organization_that_authenticated == organization_of(repository_written_to)`

An attacker who legitimately administers their own GitHub organization "A" onboarded into this shared Shipit instance necessarily knows/controls A's `webhook_secret` (they configured the GitHub App and copied the secret into their own onboarding flow, per `docs/setup.md`). That attacker can then POST an arbitrary raw JSON body directly to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = `"org-A"` → selects org A's secret, which the attacker can correctly HMAC-sign themselves.
- `repository.full_name` = `"org-B/victim-repo"` → used by every `Handlers::Handler` subclass (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*`) to locate and mutate `org-B`'s stacks.

### Impact Explanation
This lets an org-A-scoped attacker forge cross-repository writes into org B's stacks without ever compromising org B's credentials, satisfying the "cross-repository writes" Critical bucket: e.g. `PushHandler`/`GithubSyncJob` can be made to believe org B's repository received a push and sync its head SHA, and `StatusHandler` can inject arbitrary commit statuses (`state`, `context`, `target_url`, `description`) onto org B's commits, directly influencing whether Shipit considers a commit deployable/CI-green for org B's deploy pipeline.

### Likelihood Explanation
Requires only that the shared Shipit instance is configured with more than one GitHub organization (each with its own `webhook_secret`) — a supported, documented configuration (`test/dummy/config/secrets_double_github_app.yml`, `Shipit.github(organization:)`), plus knowledge of one's own organization's webhook secret, which every onboarded org's administrator legitimately possesses. No GitHub App private key, `ApiClient` token, or repository write access on the victim org is needed.

### Recommendation
After a webhook signature is verified for organization X, reject (or scope) the payload if `repository.full_name`'s owner segment does not match X, i.e. enforce `repository.owner.login == repository.full_name.split('/').first == verified_organization` before dispatching to any handler, instead of trusting `full_name` unconditionally in `Handlers::Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `org-A` and `org-B`, each with a distinct `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the legitimate admin of `org-A` (who knows `org-A`'s `webhook_secret`), craft a `push` event JSON body where `repository.owner.login = "org-A"` but `repository.full_name = "org-B/victim-repo"`.
3. Compute `X-Hub-Signature: sha1=HMAC_SHA1(org-A secret, raw_body)` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-A")` and the signature validates successfully. [7](#0-6) 
5. `PushHandler`/other handlers resolve the target stack via `payload.dig('repository', 'full_name')` = `"org-B/victim-repo"`, applying the forged event to org B's stack. [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
