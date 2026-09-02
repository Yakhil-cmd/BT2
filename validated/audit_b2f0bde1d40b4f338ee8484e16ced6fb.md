### Title
Webhook signature verification uses an attacker-controlled organization field, letting requests to orgs with no `webhook_secret` forge events for any other repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC secret) to verify a webhook against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the *unverified* JSON body. The webhook handlers, however, resolve the `Repository`/`Stack` to act on using a different field of the same unverified body: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, and every handler under `app/models/shipit/webhooks/handlers/pull_request/*`). Because `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected org has no `webhook_secret` configured (`lib/shipit/github_app.rb:76-83`), and Shipit's own setup docs and example secrets files document `webhook_secret` as **optional** and default to `nil` (`docs/setup.md:71`, `config/secrets.development.example.yml:11`, `test/dummy/config/secrets_double_github_app.yml:46`), an attacker can pick an `owner.login`/`organization.login` value that maps to an org with no secret configured, then put an arbitrary `repository.full_name` in the same payload, and Shipit will treat the whole payload as authentic for that other repository.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` does:

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

`repository_owner` comes from the raw, unauthenticated JSON body — the same body the signature is supposed to protect — and is used only to pick which `GitHubApp`/secret is used for verification.

`GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`):

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

If the org selected via `repository_owner` has no `webhook_secret` (an explicitly supported/optional configuration per `docs/setup.md` — "Webhook secret (optional)" — and the shipped example `config/secrets.development.example.yml`), verification is bypassed entirely and returns `true` regardless of the `X-Hub-Signature` header or body content.

Once past `verify_signature`, the actual event handlers never re-check `repository.owner.login`. They resolve the target `Repository`/`Stack` from a **different** field, `repository.full_name`:
- `Shipit::Webhooks::Handlers::Handler#repository_name` → `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), used by `PushHandler`.
- All pull-request handlers resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (e.g. `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`, `closed_handler.rb:49-53`, `labeled_handler.rb:65-68`, `unlabeled_handler.rb:59-63`, `label_capturing_handler.rb:110-114`).

This is a binding break: the entity that is authenticated by `verify_signature` (`repository.owner.login` / `organization.login`) is not the entity acted upon by the handlers (`repository.full_name`). Both fields live in the same untrusted payload, so an attacker who knows (or discovers, e.g. via the documented default of "optional"/"nil" secret) that any one configured organization has `webhook_secret: nil` can craft a single POST to `/webhooks` where `repository.owner.login` is that unprotected org (making `verify_webhook_signature` trivially return `true`) while `repository.full_name` names a completely different, actually-secret-protected repository/organization tracked by the same Shipit instance. No secret, token, or session of any kind is required — only that some organization configured in this Shipit instance has no webhook secret, which is the documented default.

### Impact Explanation
With signature checks defeated this way, an unauthenticated attacker can trigger any handler in `Shipit::Webhooks::DEFAULT_HANDLERS` against any repository/stack Shipit knows about, independent of that repository's own organization's webhook secret:
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb`) forces `stack.sync_github(expected_head_sha: ...)` for the targeted repository/branch, which can prematurely trigger the stack's normal GitHub sync/continuous-delivery pipeline.
- The pull-request handlers create/archive `ReviewStack` records using data taken entirely from the forged payload rather than verified GitHub state — e.g. `ReviewStackAdapter#create!`/`#stack_attributes` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:72-98`) sets `branch: params.pull_request.head.ref` directly from attacker-controlled JSON — and `#archive!`/`#unarchive!` call `stack.deprovision`, `stack.archive!`, `stack.unarchive!` on real review stacks belonging to a repository the attacker did not "authenticate" as.

This is a cross-repository write / unauthorized action against stacks that the requester was never validated against, satisfying the Critical/High impact bar ("cross-repository writes ... or an unauthorized deploy, rollback").

### Likelihood Explanation
Likelihood is high for any Shipit deployment that follows the documented setup: `webhook_secret` is explicitly called out as optional in `docs/setup.md`, and both shipped example configs (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`) ship with `webhook_secret: # nil`. Any multi-organization Shipit instance (a documented supported configuration, see "Using Multiple Github Applications" in `docs/setup.md`) where at least one configured organization omits the secret exposes every other organization's repositories to forgery, with zero credentials needed by the attacker — only network access to the public `/webhooks` endpoint.

### Recommendation
- Do not derive the verification key from attacker-controlled payload fields decoupled from the field used for authorization decisions; verify the signature using a secret bound to the specific `repository.full_name` that will actually be acted upon, not `repository.owner.login`/`organization.login`.
- Treat a missing/`nil` `webhook_secret` as a hard misconfiguration (refuse to process events, not "verified = true"), rather than silently disabling verification.
- Ensure the same field used to select the verification key is also the field the handlers use to select which repository/stack to mutate, closing the two-fields-in-one-payload gap.

### Proof of Concept
Preconditions: a Shipit instance configured with multiple GitHub organizations (`config/secrets.yml` "Using Multiple Github Applications" style) where organization `unsecured-org` has `webhook_secret` unset/nil (the documented default), while organization `victim-org` has a real secret and owns a tracked repository `victim-org/app` with an open PR and active review stacks.

```
POST /webhooks HTTP/1.1
Host: shipit.example.com
Content-Type: application/json
X-Github-Event: pull_request
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "action": "closed",
  "number": 42,
  "pull_request": { "id": 1, "number": 42, "url": "...", "title": "x", "state": "closed",
                     "additions": 0, "deletions": 0,
                     "head": { "sha": "deadbeef", "ref": "evil-branch" },
                     "user": { "login": "attacker" }, "assignees": [], "labels": [] },
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/app" },
  "sender": { "login": "attacker" }
}
```

`repository_owner` resolves to `unsecured-org` → `Shipit.github(organization: "unsecured-org")` has no `webhook_secret` → `verify_webhook_signature` returns `true` unconditionally (any/garbage `X-Hub-Signature` value works). The request then reaches `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler`, which resolves `repository` via `params.repository.full_name` = `"victim-org/app"` and calls `review_stack.archive!`, deprovisioning and archiving a real review stack belonging to `victim-org` — a repository the attacker never authenticated against. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-98)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end

          def environment
            "pr#{params.number}"
          end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```
