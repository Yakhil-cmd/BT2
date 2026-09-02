### Title
Webhook signature verification binds to `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field, enabling cross-organization writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's webhook secret to verify the request against based on `repository.owner.login` (or `organization.login`) in the JSON payload, but every `Shipit::Webhooks::Handlers::Handler` subclass — including `PushHandler` and the status/check_suite/etc. handlers — resolves the `Stack`/`Repository` to *act on* using the independent `repository.full_name` field. Nothing ties these two fields together, so a payload can be legitimately signed for organization A while acting on organization B's repository.

### Finding Description
`verify_signature` computes the organization used for HMAC verification purely from the payload itself: [1](#0-0) [2](#0-1) 

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
```

`Shipit.github(organization:)` looks up a per-organization `GithubApp` configuration (raising `Shipit::GithubOrganizationUnknown` for unknown orgs), meaning Shipit is designed to support multiple onboarded GitHub organizations, each potentially with its own `webhook_secret` [3](#0-2) . The HMAC (`OpenSSL::HMAC.hexdigest` compared via `SecureCompare`) only proves the raw body was signed with *that particular organization's* secret [4](#0-3) ; it says nothing about which repository the payload's other fields describe.

Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers that resolve the target `Stack` via a *different* field: [5](#0-4) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` (and other event handlers built on the same base class) then acts on whatever `Stack`s match `repository_name`: [6](#0-5) 

The binding that should hold is: `organization whose webhook_secret authenticated the request == organization owning the repository the handler writes to`. Because `repository.owner.login` (used for signature selection) and `repository.full_name` (used for the write target) are two independent, attacker-controlled JSON fields inside the same signed body, an organization admin who legitimately controls org A's webhook secret can craft a payload where `repository.owner.login = "orgA"` but `repository.full_name = "orgB/victim-repo"`. The signature is computed and verified correctly (it's a valid signature for org A), yet the handler operates against org B's stack.

### Impact Explanation
This breaks the equality `organization authenticated == repository written`. On a multi-tenant Shipit deployment (multiple GitHub organizations onboarded, each with its own webhook secret — the exact scenario `Shipit.github(organization:)`/`GithubOrganizationUnknown` is built for), any org that is validly onboarded can forge webhook events (`push`, `status`, `check_suite`, `deployable_status`, `merge_status`, `pull_request`, etc.) that are processed as if they came from a different, unrelated organization's repository. Depending on the handler this can:
- Force `GithubSyncJob`/`stack.sync_github` to run against a foreign stack.
- Inject fabricated commit statuses (`status` handler) marking foreign commits as CI-green, influencing `deployable?` and continuous-deployment/merge-queue logic for a repository the attacker does not own.

This is a cross-repository write across trust boundaries and can lead to unauthorized deploy eligibility being manufactured for a repository outside the attacker's authorization scope — matching the Critical "cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Likelihood is High for any Shipit installation onboarding more than one GitHub organization: the attacker only needs to be an administrator of their own, legitimately onboarded org (an "unprivileged" actor with respect to any other org's repos) and the ability to send an arbitrary POST to the public `/webhooks` endpoint with a correctly-computed HMAC using their own known secret.

### Recommendation
Cross-check the field used for signature-organization selection against the field used for target-repository resolution — e.g. require that `repository.full_name.split('/').first.casecmp(repository_owner) == 0` before dispatching to handlers, or better, resolve the target `Repository`/`Stack` using the same verified `repository_owner` value rather than a separate unauthenticated `full_name` field.

### Proof of Concept
1. Assume a Shipit instance with two onboarded organizations, `orgA` (attacker-controlled) and `orgB` (victim), each configured with distinct `webhook_secret`s under `Shipit.github(organization: ...)`.
2. Attacker (an admin of `orgA`) builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist on orgB/victim-repo>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, raw_body)` using the secret they legitimately possess for `orgA`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "orgA")` and successfully verifies the signature.
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")` and triggers `stack.sync_github(expected_head_sha: ...)` on `orgB`'s stack — an action the attacker was never authorized to perform.

### Citations

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

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
