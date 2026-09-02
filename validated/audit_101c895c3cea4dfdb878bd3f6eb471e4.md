### Title
Signature verification org (`repository.owner.login`) is never checked against the mutation-target org (`repository.full_name`), allowing cross-tenant `ReviewStack` archival - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to HMAC-verify the request against using `params.dig('repository','owner','login')`, while `ClosedHandler#repository`/`#review_stack` looks up the target `Repository` and `ReviewStack` using the independent `params.repository.full_name` field. Nothing ties these two fields together, so a payload whose `repository.owner.login` names one org (the one whose secret validated the request) and whose `repository.full_name` names a different org's repo will pass verification and still archive the second org's `ReviewStack`.

### Finding Description
Binding claimed: `org(secret that verified request) == org(ReviewStack that gets archived)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and verifies the signature with `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 
- The same raw, unmodified `params` (parsed straight from `request.raw_post`) is then dispatched to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [2](#0-1) 
- `ClosedHandler#repository` derives the actual mutated `Repository` from a **different** JSON field, `params.repository.full_name`, with no reference back to `repository.owner.login`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. `#review_stack` then scopes the `ReviewStack` lookup to that repository and calls `archive!` on it. [3](#0-2) 
- `ReviewStackAdapter#archive!` finds the stack purely `scope.find_by(environment:)` (`environment = "pr#{params.number}"`) inside that scope and calls `stack.archive!(user, ...)` unconditionally if present and not already archived. [4](#0-3) 
- `GitHubApp#verify_webhook_signature` also returns `true` unconditionally when the org selected for verification has no `webhook_secret` configured, which is an explicitly optional setting in this codebase's own config examples (`webhook_secret: # nil` appears in `test/dummy/config/secrets.yml`, `secrets_double_github_app.yml`, and `config/secrets.development.shopify.yml`). [5](#0-4) 

Root cause: signature verification and the record-mutating repository lookup independently read two different, attacker-supplied leaves of the same `repository` JSON object (`owner.login` vs `full_name`), and no code path cross-checks that `full_name`'s owner segment equals `repository_owner`.

Exploit flow: an attacker who can get a request past `verify_signature` for org A (either because org A's `webhook_secret` is unset/nil in the Shipit deployment, making verification a no-op, or because the attacker otherwise possesses a valid signature for org A) crafts a `pull_request` `closed` payload where `repository.owner.login = "org_a"` but `repository.full_name = "victim_org/victim_repo"` and `number` matches an existing PR/ReviewStack in `victim_org/victim_repo`. The request passes `verify_signature` (keyed off `org_a`) and then `ClosedHandler` archives `victim_org`'s live `ReviewStack`.

Existing guards do not stop this: `drop_unhandled_event` and the `ExplicitParameters` schema only check field presence/types, not cross-field organizational consistency; `verify_signature` never inspects `repository.full_name`; `Repository.from_github_repo_name` and the `review_stacks` scope have no notion of "the org that was cryptographically verified."

### Impact Explanation
A successfully forged/mismatched event causes `Shipit::ReviewStack#archive!` to run for a repository/org that never authenticated the request, tearing down a live review/deploy environment (`stack.remove_from_provisioning_queue`, `stack.deprovision`, `stack.archive!`) belonging to another tenant. This is a cross-tenant, unauthenticated mutation of another organization's deploy stack, matching the "payload for one repository mutating another's stack" critical category. It is repeatable against any repo/PR number combination the attacker can guess or observe, and is not limited to `ClosedHandler` — the same `params.repository.full_name`-vs-`repository_owner` decoupling affects every other `pull_request` handler that follows the identical pattern (`OpenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `LabelCapturingHandler`), all of which independently derive `repository` from `params.repository.full_name`. [6](#0-5) [7](#0-6) 

### Likelihood Explanation
Exploitability hinges on the attacker being able to pass `verify_signature` for *some* org name they place in `repository.owner.login`. This engine's own signature-check code makes that trivial whenever that org's `webhook_secret` is left blank (`return true unless webhook_secret`), a configuration this repo documents as optional and ships as the default in its own secrets templates and test fixtures. In that (common, non-hardened) deployment posture, the attacker needs no secret at all — only the ability to POST an arbitrary JSON body to `/webhooks` with a matching `X-Github-Event: pull_request` header, `action: "closed"`, an arbitrary `repository.owner.login`, and the victim's real `repository.full_name` + PR `number`. If every configured org in the deployment does set a `webhook_secret`, the attacker instead needs a valid signature for at least one configured org, which is a stronger precondition but still independent of ownership of the org named in `repository.full_name`. Either way, the bug — verification org and mutation-target org being different, uncorrelated fields — is present in the code regardless of secret configuration.

### Recommendation
In `WebhooksController#verify_signature`/`create`, or inside each `pull_request` handler's `repository` resolution, enforce that the org segment of `params.repository.full_name` matches the `repository_owner` (or `organization.login`) that was used to select the `webhook_secret` for verification, and reject the request (e.g., `head(422)`) on mismatch. Additionally, require `webhook_secret` to be present for all configured orgs in production (or fail startup / log loudly) rather than silently treating a blank secret as "verification passes."

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "pull_request closed event whose repository.full_name org differs from the verified owner archives another org's ReviewStack" do
  # Arrange: victim org has a live, provisioned ReviewStack for PR #5
  victim_repo = Shipit::Repository.create!(github_repo_name: "victim_org/victim_repo", review_stacks_enabled: true, provisioning_behavior: :allow_all)
  victim_stack = victim_repo.review_stacks.create!(environment: "pr5", branch: "feature")
  assert_not victim_stack.archived?

  # Attacker's org ("attacker_org") has no webhook_secret configured (default/no-op verification),
  # or GithubHook#verify_signature is stubbed true to simulate a validly-signed request for "attacker_org".
  Shipit.stubs(:github).with(organization: "attacker_org").returns(stub(verify_webhook_signature: true))

  request.headers['X-Github-Event'] = 'pull_request'
  payload = {
    action: "closed",
    number: 5,
    pull_request: { id: 1, number: 5, url: "u", title: "t", state: "closed",
                     additions: 1, deletions: 1, head: { sha: "abc", ref: "feature" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: {
      full_name: "victim_org/victim_repo",     # <-- points at the VICTIM's repo/stack
      owner: { login: "attacker_org" }          # <-- org used to select the signature-verifying secret
    },
    sender: { login: "attacker" }
  }.to_json

  # Binding under test, BEFORE:
  assert_equal false, victim_stack.reload.archived?

  post :create, body: payload, as: :json

  # Binding under test, AFTER: verified-org ("attacker_org") != archived-stack-org ("victim_org"),
  # yet the archive happened.
  assert victim_stack.reload.archived?, "victim_org's ReviewStack was archived by a request verified as attacker_org"
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
