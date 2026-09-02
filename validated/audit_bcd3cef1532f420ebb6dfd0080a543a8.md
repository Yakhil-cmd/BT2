### Title
Webhook signature is verified against the payload's `repository.owner.login` while handlers act on the payload's `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to check the `X-Hub-Signature` against using the organization login taken from the *request body itself* (`repository.owner.login` / `organization.login`), not from any pre-established, trusted binding. Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` to write to using a *different* field from the same untrusted body: `repository.full_name`. These two fields are never cross-checked against each other, so a signature that is valid for organization A can be attached to a payload that names a repository belonging to organization B.

### Finding Description
`WebhooksController#verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up per-organization app configuration (each org can have its own `app_id`/`webhook_secret`), so in a multi-org Shipit deployment there are as many independent secrets as configured organizations. `GitHubApp#verify_webhook_signature` HMACs the *raw request body* with the secret belonging to whichever organization the body claims to be from:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [2](#0-1) 

Once the signature check passes, every event handler determines the affected repository not from `repository.owner.login` but from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PullRequest::OpenedHandler` (and its siblings) independently re-derive the repository the same way and then create/mutate records scoped to it:
```ruby
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
    Shipit::NullRepository.new
end
...
Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
  .new(params, scope: repository.review_stacks).find_or_create!
``` [4](#0-3) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by X-Hub-Signature (payload.repository.owner.login)` == `repository whose Stack/records the handler mutates (payload.repository.full_name)`

Before the attack, `verify_signature` implicitly assumes both fields describe the same GitHub organization because in a legitimate GitHub-originated webhook they always do (GitHub itself populates both). After the attack, an attacker who knows (or controls) the `webhook_secret` for *one* configured organization (e.g., because they own/administer that org and its GitHub App, a normal, unprivileged relationship to the Shipit instance which requires no Shipit session, `ApiClient` token, or `github_access_token`) can POST directly to the public `/github/webhooks` endpoint with a payload whose `repository.owner.login` is their own org (so `Shipit.github(organization: repository_owner)` picks the secret they know) and correctly HMAC-sign the raw body with that secret, while setting `repository.full_name` to any other repository/organization tracked by the same Shipit instance. `verify_signature` passes, and the handler proceeds to act on the victim repository.

### Impact Explanation
This is a cross-repository write: an attacker who only controls their own org's webhook secret can drive Shipit to mutate state scoped to a different, victim organization's repository that they have no authorization over — e.g. `PullRequest::OpenedHandler`/`ReviewStackAdapter` will create/find review `Stack`s under the victim repository, `PushHandler`/`StatusHandler`/`CheckSuiteHandler` will record commit statuses and check-run results against victim commits, and `MembershipHandler` will create/modify `Team`/`User` membership records — all attributed to the victim repository while authenticated only as the attacker's own organization. Because Shipit's deploy/merge pipelines (deployability checks, merge queue, CI status gating) consume this forged commit/check state, this can be leveraged toward triggering unauthorized merges or deploy gating bypass for repositories the attacker does not control, satisfying the "cross-repository writes" / "unauthorized merge" impact bar. This requires a Shipit deployment configured with multiple GitHub organizations (the multi-org `github:` config format shown in `config/secrets.development.example.yml`), each with an independently-known secret to at least one org the attacker legitimately administers.

### Likelihood Explanation
Exploitability requires no Shipit session, `ApiClient` token, or stolen credential — only knowledge of one configured organization's `webhook_secret`, which is plausible for any org owner/administrator of a GitHub App connected to a shared Shipit instance serving multiple organizations. The webhook endpoint (`/github/webhooks`) is public by design (it must accept unauthenticated POSTs from GitHub), so the forged request can be sent directly without any interaction with GitHub. The only precondition is a multi-organization Shipit deployment, which is an explicitly supported and documented configuration.

### Recommendation
Bind the field used for secret selection to the field used for repository resolution before trusting either: after selecting `github_app` via `repository_owner`, verify that `repository.full_name`'s owner segment (or `organization.login`) matches `repository_owner` exactly, and reject the webhook otherwise. Alternatively, resolve the target `Repository`/`Stack` first and require that its configured organization equals the organization whose secret validated the signature, rather than trusting `full_name` independently in every handler.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret `S_A`, known to the attacker because they administer that org's GitHub App) and `victim-org` (a different, unrelated org whose repositories are tracked by the same Shipit instance).
2. Attacker crafts a `pull_request` "opened" webhook JSON body with:
   - `"organization": {"login": "attacker-org"}`, `"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}`
   - valid `pull_request`, `sender`, etc. fields required by `OpenedHandler`'s param schema.
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` and POSTs directly to `/github/webhooks` with `X-Github-Event: pull_request`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and successfully verifies the signature against `S_A`. [5](#0-4) 
5. `Webhooks.for_event('pull_request')` dispatches to `PullRequest::OpenedHandler`, which resolves `repository` via `params.repository.full_name` ("victim-org/victim-repo") and calls `ReviewStackAdapter.find_or_create!` scoped to that victim repository's `review_stacks`, creating/mutating Shipit records for a repository the attacker never authenticated as. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-54)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

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
