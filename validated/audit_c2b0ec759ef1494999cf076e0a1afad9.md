### Title
Webhook signature is bound to `repository.owner.login`, but every handler acts on `repository.full_name` — cross-organization/cross-repository writes with any single organization's webhook secret - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a delivery against using `repository_owner`, which reads `repository.owner.login` from the JSON body. [1](#0-0) [2](#0-1)  Every event handler, however, resolves the actual `Stack`/`Repository` to mutate using a different field of the same JSON object: `repository.full_name`. [3](#0-2) [4](#0-3)  Nothing checks that the `full_name`'s owner segment matches `owner.login`. This is the exact bug class from the report: two fields inside the same iterated/parsed structure are conflated — one used to establish trust, a different one used to perform the write.

### Finding Description
In a multi-tenant Shipit deployment (`Shipit.github_organizations`/`Shipit.github_app_config`), each GitHub organization onboarded to the instance has its own `webhook_secret` in `secrets.github.<org>.webhook_secret`. [5](#0-4)  The webhook signature check picks the secret to verify against solely from `repository.owner.login` (or `organization.login` as a fallback when `repository` is absent):
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw JSON body to handlers. [7](#0-6)  Every default handler (`PushHandler`, all `PullRequest::*Handler`s, etc.) resolves the target `Repository`/`Stack` using `repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

The `owner.login` and `full_name` fields are never cross-validated against each other anywhere in the controller or in `Handler`. Because a HMAC signature over the whole raw body only proves "whoever crafted this exact JSON blob knows organization X's secret" — it does not prove that the blob's internal fields are internally consistent with what a legitimate GitHub delivery for org X would contain. Any party who legitimately possesses the webhook secret for **one** onboarded organization (e.g., a customer/team that manages its own GitHub App installation and configured `webhook_secret` on a shared Shipit instance) can freely construct a JSON body where `repository.owner.login == "their-org"` (to satisfy signature routing) while `repository.full_name == "victim-org/victim-repo"` (to target any other tracked stack).

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," letting an attacker with only one org's webhook secret perform cross-repository/cross-organization writes on a shared Shipit instance:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on an arbitrary tracked stack, forging sync state for a repo the attacker doesn't own on GitHub. [4](#0-3) 
- `PullRequest::OpenedHandler`/`ClosedHandler`/`LabelCapturingHandler` etc. create/update `PullRequest` records and drive `ReviewStackAdapter` (which can create/destroy review stacks) for any repository resolved via `params.repository.full_name`, entirely independent of which org's secret authenticated the request. [8](#0-7) 
- `StatusHandler` writes arbitrary commit statuses for any `sha` present in the datastore, unrelated to the authenticating org (it doesn't even scope by repository, compounding the issue). [9](#0-8) 

This satisfies the "cross-repository writes" / "unauthorized deploy" high-impact bar, since `sync_github` and review-stack creation/close feed directly into what commits are deployable and which review-stack deploy flow proceeds.

### Likelihood Explanation
Requires only a webhook secret belonging to any one organization already configured on the shared Shipit instance (a routine, unprivileged-relative-to-other-tenants credential in a multi-org deployment) and the ability to POST an arbitrary JSON body to the public `/webhooks` endpoint (no other authentication is required there). No GitHub-side spoofing is needed at all — the attacker crafts the JSON directly and signs it themselves with their own known secret.

### Recommendation
In `WebhooksController`/`Handler`, require that the field used to select the webhook secret and the field used to resolve the target repository are the same, and reject the payload if `repository.full_name`'s owner segment does not match `repository.owner.login` (or `organization.login`). Alternatively, derive the target repository strictly from `repository.owner.login` instead of trusting `full_name` for routing.

### Proof of Concept
1. Organization `attacker-org` is legitimately onboarded to a shared Shipit instance with its own `webhook_secret = S`.
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature validates successfully because it was computed with `attacker-org`'s own secret. [1](#0-0) 
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` from `full_name` and calls `stack.sync_github` on the victim's stack — a write the attacker has no legitimate authority over. [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-63)
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
