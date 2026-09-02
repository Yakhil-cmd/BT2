### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` and `repository.full_name` bypasses signature verification and mutates an unrelated victim stack's `PullRequest` labels (which become deploy environment variables) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App config used for HMAC verification using `params.dig('repository','owner','login')`, while `LabelCapturingHandler` (and other `pull_request` handlers) resolve the *target* repository/stack using the independent field `params.repository.full_name`. Because these are two separate, attacker-controlled JSON fields with no cross-check, an attacker can point `repository.owner.login` at a Shipit-configured org that has no `webhook_secret` (bypassing verification entirely) while pointing `repository.full_name` at a completely different, victim organization's repository whose review stack is `review_stacks_enabled: true, allow_all`.

### Finding Description
The broken binding, stated as an equality that the system implicitly relies on but never enforces:
`owner_used_for_verification == owner_of(repository.full_name)` — this must hold for signature verification to actually authenticate the repository/stack being mutated, but it is never checked.

Trace:
1. `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-38` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`) and looks up `Shipit.github(organization: repository_owner)`.
2. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) returns `true` unconditionally when `@webhook_secret` is blank (`lib/shipit/github_app.rb:50,77`) — a state that is explicitly supported/documented (see `docs/setup.md`, `template.rb`, and multiple fixture configs with `webhook_secret: # nil`).
3. Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire attacker-controlled JSON body* to handlers such as `LabelCapturingHandler` (`app/controllers/shipit/webhooks_controller.rb:10-12`).
4. `LabelCapturingHandler#repository` resolves the target repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114`) — this reads `repository.full_name`, a field entirely independent from the `repository.owner.login` field used in step 1.
5. For `action == "reopened"` and an existing, non-archived stack, `capture_labels?` → `reopened_active_stack?` returns true (`label_capturing_handler.rb:70-72,86-88`), and `capture_labels` persists `params.pull_request.labels.map(&:name)` onto the victim stack's `PullRequest` record (`label_capturing_handler.rb:98-102`).
6. `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) merges each stored label, upcased, as `"true"` into the deploy environment (`LABEL_NAME=true`), which flows into subsequent `Command`/`PTY.spawn` invocations for that stack's deploy/provisioning tasks.

Exploit flow: attacker crafts a `pull_request` webhook body with `repository.owner.login = "no-secret-org"` (a Shipit-configured org with blank `webhook_secret`) and `repository.full_name = "victim-org/victim-repo"` (a real, unrelated repository with `review_stacks_enabled: true`, `provisioning_behavior: allow_all`, and an active, non-archived review stack for some open PR number). `verify_signature` authenticates using `no-secret-org`'s config, always succeeds because that org's secret is blank, and the request is accepted with no HMAC at all. `LabelCapturingHandler` then mutates the victim repo's review stack `PullRequest.labels` using data taken from `repository.full_name`, not from the authenticated org.

No existing guard prevents this: `verify_signature` never compares `repository_owner` to any derived owner of `repository.full_name`; `ExplicitParameters` only validates types/presence, not cross-field consistency; `Repository.from_github_repo_name` performs a plain lookup by string and has no relationship to the org used for HMAC verification.

### Impact Explanation
This is a payload for one organization/repository (whose secret authenticated the request, or lack thereof) mutating another organization's stack — matching the Critical "payload for one repository mutating another's stack" class. The attacker-controlled labels become uppercased environment variables (`LABEL_NAME=true`) injected into the victim review stack's deploy/provisioning environment, which is consumed by `shipit.yml`-driven `Command`/`PTY.spawn` executions for that stack. Combined with `review_stacks_enabled: true, allow_all` (auto-provisioning external PRs run `shipit.yml`), this environment-variable injection can influence build/deploy behavior on the victim's deploy host. The attack is repeatable against any repository/org pair as long as at least one Shipit-configured org has a blank `webhook_secret` (a documented, common configuration for local/dev instances, and per fixtures, easy to encounter in real deployments that use the multi-org github config without setting every org's secret).

### Likelihood Explanation
Preconditions: (1) Shipit must have at least one configured GitHub organization with no `webhook_secret` (explicitly supported by `Shipit.github`/`GitHubApp`, and shown as a normal configuration state in `docs/setup.md`, `template.rb`, and various secrets fixtures); (2) a victim repository/stack with `review_stacks_enabled: true`, `allow_all`, and an existing non-archived review stack tied to an open PR number the attacker can guess or discover (PR numbers are public/sequential on GitHub). No authentication, session, API token, or GitHub secret is required — the attacker only needs to send a single unauthenticated `POST /webhooks` request with a crafted JSON body and the `X-Github-Event: pull_request` header. This is trivially repeatable and requires no privileged access.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, derive the authorization context strictly from the field(s) actually used downstream by handlers (`repository.full_name`), not a separate `repository.owner.login`/`organization.login` field, or explicitly validate that `repository.full_name` starts with `"#{repository_owner}/"` before dispatching to handlers. Additionally, consider treating a blank `webhook_secret` as a hard misconfiguration error in production environments rather than silently disabling verification (`lib/shipit/github_app.rb#verify_webhook_signature`), and add a cross-field consistency check so `Repository.from_github_repo_name` results are also cross-validated against the authenticated organization.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "no-secret org allows forging a pull_request event that mutates a different org's review stack" do
  # Precondition: configure "no-secret-org" with a blank webhook_secret alongside the existing
  # "shopify" org config (secrets_double_github_app.yml style), and set up
  # shipit_repositories(:shipit) with review_stacks_enabled: true, provisioning_behavior: :allow_all,
  # plus an existing non-archived ReviewStack + PullRequest for PR number N (e.g. via OpenedHandler).

  victim_stack = <the review stack created above>
  assert_empty victim_stack.pull_request.labels

  payload = payload_parsed(:pull_request_reopened)
  payload["repository"]["owner"]["login"] = "no-secret-org"          # used ONLY for verify_signature
  payload["repository"]["full_name"] = "shopify/shipit-engine"        # used to resolve the TARGET stack
  payload["pull_request"]["labels"] = [{ "name" => "malicious-flag" }]

  @request.headers["X-Github-Event"] = "pull_request"
  # no X-Hub-Signature header at all

  post :create, body: payload.to_json, as: :json
  assert_response :ok

  victim_stack.reload
  # BROKEN BINDING: owner used for verification ("no-secret-org") != owner of full_name ("shopify"),
  # yet the victim stack, authenticated by neither its own nor any matching secret, was mutated.
  assert_includes victim_stack.pull_request.labels, "malicious-flag"
  assert_equal "true", victim_stack.env["MALICIOUS_FLAG"]
end
```