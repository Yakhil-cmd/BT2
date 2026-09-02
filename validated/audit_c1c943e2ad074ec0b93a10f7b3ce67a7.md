### Title
Cross-org repository confusion in `ClosedHandler` allows unauthorized `ReviewStack` archival - ([File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`ClosedHandler#process` resolves the target `Repository`/`ReviewStack` from `params.repository.full_name`, while `WebhooksController#verify_signature` selects the GitHub App/secret to verify the request against using a *different* field, `params.dig('repository','owner','login')` (`repository_owner`). Because both fields come from the same attacker-supplied JSON body and are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` when no `webhook_secret` is configured for the resolved organization, an attacker can pick a `repository.owner.login` that resolves to an app config with no `webhook_secret` while pointing `repository.full_name` at an arbitrary victim repo/PR, causing that victim's `ReviewStack` to be archived.

### Finding Description
Broken binding: `repository_owner` (used to select the signing key in `verify_signature`) **must equal** the owner embedded in `repository.full_name` (used by the handler to select the repository/ReviewStack to mutate). The code never enforces this equality.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` comes straight from the JSON body (`app/controllers/shipit/webhooks_controller.rb:59-62`), then calls `github_app.verify_webhook_signature(header, raw_body)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) returns `true` unconditionally `unless webhook_secret` is configured for that organization — i.e., for any org entry lacking a `webhook_secret`, signature verification is a no-op and any payload passes with any/no `X-Hub-Signature` header.
- `ClosedHandler#repository` (app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:49-53) resolves the actual `Shipit::Repository` from `params.repository.full_name`, an entirely separate JSON field from `repository.owner.login`.
- `ClosedHandler#process` then calls `review_stack.archive!` (line 44), where `review_stack` is looked up in the scope of that resolved repository (line 55-59), tearing down/transitioning the `ReviewStack` for whatever PR number is named in the payload.

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, a body where `repository.owner.login = "attacker-org"` (an org configured in Shipit with no `webhook_secret`, or one the attacker otherwise controls) but `repository.full_name = "victim-org/victim-repo"`, `action: "closed"`, and `number`/`pull_request.number` matching a real victim PR that has an active `ReviewStack`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, which has no secret, so `verify_webhook_signature` returns `true` regardless of the signature header supplied. The request proceeds to `ClosedHandler`, which resolves `victim-org/victim-repo` and archives the victim's review stack.

Existing guards do not stop this: `drop_unhandled_event` only checks event type existence; the `ExplicitParameters` schema only validates types/presence of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name`; there is no model validation tying a `Repository`'s owner to the webhook's authenticated organization.

### Impact Explanation
An attacker who controls (or can name) an organization/app config lacking a `webhook_secret` can force the destruction/state transition of any other tenant's `ReviewStack` by crafting a payload whose `repository.full_name` names the victim repo. This is a payload for one (attacker-influenced) organization mutating another repository's review-stack state — matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any repository/PR number for which the attacker can guess or observe an open review stack, and it applies engine-wide across every tenant sharing the Shipit instance, since `verify_signature`'s org-selection is entirely attacker-controlled input.

### Likelihood Explanation
Exploitability depends on the operator's `secrets.github` configuration: it requires at least one configured organization entry with no `webhook_secret` set (or one whose secret the attacker can otherwise satisfy), which is the "missing-webhook_secret bypass" explicitly named in the finding. This is a realistic misconfiguration risk in multi-org Shipit deployments (the schema supports per-org config via `github_app_config`, and nothing enforces every org to define a secret). Given that precondition, exploitation costs nothing beyond a single unauthenticated HTTP POST with a hand-crafted JSON body — no GitHub credentials, sessions, or API tokens are needed, satisfying the attacker model.

### Recommendation
Enforce that the organization used to verify the signature matches the actual owner of the repository the payload claims to act on. Concretely:
- In `WebhooksController#verify_signature`, after resolving `repository_owner`, also parse `repository.full_name` and require `repository.full_name.split('/').first == repository_owner` (reject with 422 otherwise).
- Alternatively/additionally, require every configured GitHub org in `secrets.github` to have a non-blank `webhook_secret`, and fail closed (not verified) when a secret is absent instead of treating it as verified (`GitHubApp#verify_webhook_signature` should not `return true unless webhook_secret`).
- In the PR handlers (`ClosedHandler`, `OpenedHandler`, etc.), re-derive the repository strictly from an owner value that has been authenticated by signature verification, not from a raw unauthenticated field in the same payload.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub calls):
```ruby
test "cross-org payload archives a victim ReviewStack via missing webhook_secret" do
  victim_repo = shipit_repositories(:shipit) # owner "shopify", say
  victim_stack = shipit_review_stacks(:some_review_stack) # belongs to victim_repo, PR #42, not merged/closed

  # Simulate an org config with no webhook_secret for "attacker-org"
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    Shipit::GitHubApp.new("attacker-org", { app_id: 1, installation_id: 1, private_key: "x" }) # no webhook_secret key
  )

  body = {
    action: "closed",
    number: 42,
    pull_request: { id: 1, number: 42, url: "u", title: "t", state: "closed",
                     additions: 1, deletions: 1,
                     head: { sha: "sha", ref: "ref" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: { full_name: "#{victim_repo.owner}/#{victim_repo.name}", owner: { login: "attacker-org" } },
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/garbage, should be irrelevant

  assert victim_stack.active?, "precondition: stack starts active"

  post :create, body: body, as: :json

  assert_response :ok
  victim_stack.reload
  assert victim_stack.archived?, "victim ReviewStack was archived by an unauthenticated cross-org request"
end
```
Assertions on both sides of the binding: before the request, `repository_owner == "attacker-org"` while `repository.full_name`'s owner segment `== victim_repo.owner ("shopify")` — they diverge; after the request, the divergence is shown to have caused a write (`victim_stack.archived?`) despite the attacker never authenticating as `victim_repo`'s organization. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
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

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
