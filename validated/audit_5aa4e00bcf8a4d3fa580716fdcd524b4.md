Confirmed: `WebhooksController#verify_signature` selects the HMAC secret using `repository.owner.login` (or `organization.login`), while every event handler (via `Shipit::Webhooks::Handlers::Handler#repository_name`) resolves the actual target repository using `repository.full_name` — a separate field in the same untrusted JSON body. Since GitHub Apps can be installed on multiple organizations, each with its own `webhook_secret`, an attacker who legitimately controls webhook delivery for "their" organization (i.e., knows that org's `webhook_secret`, e.g. because they administer a GitHub App/repo webhook in an org onboarded to this Shipit instance) can craft a raw payload where `repository.owner.login`/`organization.login` names their own org (so the correct secret is selected and their valid signature passes), but `repository.full_name` names a completely different, victim organization's repository that is already registered as a Shipit `Repository`/`Stack`. Because only the raw body's HMAC is checked — not the internal consistency of `owner.login` vs `full_name` — this passes `verify_signature` and reaches the handler.

### Title
Webhook signature verification binds only to `repository.owner.login`, letting a payload's `repository.full_name` target a different organization's stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the per-organization `webhook_secret` using `params.dig('repository','owner','login')`, but `Shipit::Webhooks::Handlers::Handler#repository_name` (used by every push/status/check_suite/pull_request handler) resolves the actually-affected `Repository`/`Stack` using the independent `repository.full_name` field from the same JSON body. The HMAC only guarantees the raw body wasn't tampered with by a third party; it does nothing to bind these two fields to the same organization. An attacker who controls delivery for Org B (and therefore knows Org B's `webhook_secret`) can set `repository.owner.login = "OrgB"` while setting `repository.full_name = "OrgA/victim-repo"`, producing a validly-signed request whose payload is nonetheless acted on against Org A's stack. [1](#0-0) [2](#0-1) 

### Finding Description
`verify_signature` derives `repository_owner` from the still-unverified request body and uses it solely to choose `Shipit.github(organization: repository_owner)`, whose `webhook_secret` is then checked against `X-Hub-Signature` and the raw body via `verify_webhook_signature`. [3](#0-2) [4](#0-3) 

Once the signature check passes (meaning only that *some* field, `repository.owner.login`, matches an organization whose secret the sender knows), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the entire raw JSON to handlers. [5](#0-4) 

Every default handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*Handler` family) inherits `stacks`/`repository_name`, which looks up the target `Repository` via `payload.dig('repository', 'full_name')` — not `repository.owner.login`. [2](#0-1) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` simply splits `"owner/name"` on `/` and does a plain lookup, with no re-check that the resolved repository's `owner` matches the organization whose secret validated the signature. [8](#0-7) 

This is precisely the analog to the reported bug class: the security boundary (which organization's secret authorized this webhook) does not equal the boundary actually enforced when the payload is acted on (which repository/stack gets written), because two independently-attacker-controlled fields of the same signed body are used for the two different purposes.

### Impact Explanation
An attacker who is a legitimate GitHub org admin/webhook operator for one organization configured in this Shipit instance (Org B) can forge push/status/check_suite/pull_request events that Shipit will apply to a *different* organization's repository/stack (Org A), as long as Org A's repository is already registered in this Shipit instance. Depending on handler:
- `PushHandler` can trigger `GithubSyncJob`/`sync_github` for Org A's stack with an attacker-chosen `after` SHA, letting the attacker manipulate which commit Shipit believes is at the head of a branch it doesn't control — a step toward an unauthorized deploy of an attacker-influenced revision on Org A's stack.
- `StatusHandler`/`CheckSuiteHandler` can forge CI/check status for Org A's commits, bypassing `require_ci`/deployable-commit checks that gate `Deploy` creation.
- Pull-request handlers can mutate `PullRequest`/`MergeRequest` state (assignees, labels, merge/review-stack status) for Org A's repository.

This crosses the "unauthorized deploy" / cross-repository-write impact bar defined in scope, since it lets a party who only controls Org B's webhook secret write into Org A's stack state.

### Likelihood Explanation
Requires the attacker to be a legitimate webhook sender for at least one organization onboarded into the same Shipit instance (i.e., know that org's `webhook_secret`) and requires the target organization's repository to already be a registered `Repository`/`Stack`. This is realistic in any multi-tenant Shipit deployment (the engine explicitly supports multiple `github:` orgs in `secrets.yml`), where trust boundaries between tenant organizations are expected to be maintained by the engine itself.

### Recommendation
After selecting the `webhook_secret` via `repository.owner.login`/`organization.login` and verifying the signature, re-derive the repository/organization used by handlers from the *same* trusted field (or explicitly assert that `repository.full_name`'s owner segment equals the `repository_owner` used for signature verification) before dispatching to handlers. Alternatively, resolve `Repository.from_github_repo_name` and confirm `repository.owner == repository_owner` (the field that was cryptographically verified) before allowing any handler to mutate state.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `orgb` (attacker-controlled webhook secret `SB`) and `orga` (victim, secret unknown to attacker), each with a `Repository`/`Stack` registered (`orga/victim-repo` exists in Shipit's DB).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist as a commit on orga/victim-repo>",
  "repository": { "owner": { "login": "orgb" }, "full_name": "orga/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(SB, body)>` using the secret they know for `orgb`.
4. POST to the webhooks endpoint with header `X-Github-Event: push`.
5. `verify_signature` loads `Shipit.github(organization: "orgb")`, verifies the signature successfully against `SB`, and passes.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orga/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim organization's stack — despite the attacker never possessing `orga`'s webhook secret. [9](#0-8) [6](#0-5) [2](#0-1)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-69)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
