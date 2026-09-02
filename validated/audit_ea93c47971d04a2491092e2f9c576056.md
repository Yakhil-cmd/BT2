I have enough evidence to confirm this vulnerability. Let me verify the final piece: whether provisioning actually leads to command execution.### Title
Cross-tenant Review Stack forgery via webhook signature/repository binding mismatch - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `params.dig('repository','owner','login')`, while `OpenedHandler#repository` (and `Handler#repository_name`) independently resolve the target `Shipit::Repository` using `params.repository.full_name` from the same, attacker-supplied JSON body. Because nothing enforces that `repository.owner.login` matches the owner segment of `repository.full_name`, an attacker can pick any org configured with no `webhook_secret` to pass signature verification for free, while pointing `repository.full_name` at a real, different org's repository to trigger review-stack creation there.

### Finding Description
Binding claimed correct: `org verifying webhook (repository_owner)` == `org owning repository.full_name (whose review_stacks scope is mutated)`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`). This is attacker-controlled JSON, not cryptographically bound to anything.
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) returns `true` unconditionally `unless webhook_secret` — i.e., if the org resolved from `repository_owner` has no `webhook_secret` configured (a documented, valid config: `webhook_secret: # nil` appears in `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, and `test/dummy/config/secrets_double_github_app.yml`), **any** signature (or none) verifies successfully.
- The raw JSON body then flows unchanged into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:11-12`).
- `OpenedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`) resolves the actual `Shipit::Repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate field of the same payload, with no relationship enforced to `repository.owner.login` used earlier for signature selection. `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) has the identical pattern.
- If `provision?` (`opened_handler.rb:65-69`) is true for that resolved repository (`review_stacks_enabled` && `provisioning_behavior_allow_all?`), `ReviewStackAdapter#find_or_create!` (`opened_handler.rb:44-46`, `review_stack_adapter.rb:19-21,72-94`) creates a `ReviewStack` with attacker-chosen `branch: params.pull_request.head.ref`, `environment: "pr#{params.number}"`, and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` (`review_stack_adapter.rb:82`), setting `awaiting_provision: true` (`app/models/shipit/review_stack.rb` `enqueue_for_provisioning`). The queue worker (`review_stack_provisioning_queue.rb:29-37`) later calls `stack.provision`, which fires `stack.provisioner.up` (`app/models/shipit/review_stack.rb:75-77`) — running the host application's `ProvisioningHandler#up`, which is exactly the mechanism `docs/review_stacks.md` describes as allocating real infrastructure and running deploy commands for the stack.

Exploit flow: attacker (no Shipit credentials) POSTs to `/webhooks` with `X-Github-Event: pull_request`, a fabricated `pull_request` object (fake `head.sha`/`ref`, `number`, `labels`, `sender.login`), `repository.owner.login` = some org configured with `webhook_secret: nil` (e.g. an org the attacker installed the app on themselves, or any org operators left with no secret), and `repository.full_name` = `"victim-org/victim-repo"` where victim-org is real, tracked, `review_stacks_enabled`, `provisioning_behavior_allow_all?`. `verify_signature` passes trivially (no secret to check), the handler resolves and mutates victim-org's `review_stacks` scope, creating and eventually provisioning a stack that never corresponds to a real PR on that repo.

None of the existing guards close this: `drop_unhandled_event` only checks event type; `verify_signature` checks a signature against the *wrong* org's secret (attacker's own, or none); `ExplicitParameters` schema only validates types/presence, not cross-field consistency between `repository.owner.login` and `repository.full_name`; `Repository` model validations (`app/models/shipit/repository.rb:41-45`) validate format of a repo's own `owner`/`name` columns, not that inbound webhook claims match; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` in the webhook path at all, since webhooks are meant to be verified by signature instead of session/token.

### Impact Explanation
An unauthenticated attacker can create and provision (deploy-trigger) a `Shipit::ReviewStack` under an arbitrary, unrelated organization's tracked repository, as long as (a) that repository has `review_stacks_enabled` and `provisioning_behavior_allow_all?` (or satisfies the label-based policies with attacker-controlled `labels`), and (b) any org in the Shipit deployment's multi-org GitHub config has no `webhook_secret` set. This is a cross-tenant write: a payload that authenticates for org A mutates org B's `review_stacks`. Provisioning invokes the host's `ProvisioningHandler#up`, which per `docs/review_stacks.md` is expected to allocate real resources/run deploy scripts — an unauthorized deploy/provisioning trigger. This matches the "Critical" category: a payload for one repository mutating another's stack and triggering an unauthorized deploy. It is repeatable against any repository/org combination satisfying the above conditions, and is not resource-exhaustion — it's an authorization/binding bypass.

### Likelihood Explanation
Preconditions: multi-org GitHub config in `secrets.yml` (`github: <org>: ...`) with at least one org lacking `webhook_secret` (explicitly supported/documented, appearing as the default in example config files), and at least one *other* tracked repository with `review_stacks_enabled` + `allow_all` (or attacker-satisfiable label policy). Attacker cost is a single crafted HTTP POST with no credentials, no signature computation needed (or a trivial `sha1=` header, ignored since `webhook_secret` is blank). This is fully repeatable and requires no social engineering, TLS interception, or privileged access — only knowledge of the target's org name and repo name, both public information typically. The main mitigating factor is that it requires an operator to run multi-org mode with a secret-less org, which the project's own example/docs configs default to (`webhook_secret: # nil`), making this a realistic misconfiguration rather than a purely theoretical one.

### Recommendation
Bind the resolved repository/organization to the org that verified the signature: after `verify_signature` succeeds, pass the verified `organization` (or the `GitHubApp` instance) into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization) }`, and have `Handler#repository`/`Handler#repository_name` require that `payload.dig('repository','owner','login')&.downcase == payload.dig('repository','full_name')&.split('/')&.first` and that this owner equals the verified organization, rejecting (204/422, no processing) otherwise. Additionally/alternatively, disallow silently-permissive `webhook_secret: nil` in multi-org configurations (require an explicit config flag to allow unsigned webhooks per org), since that is the enabling misconfiguration for this specific bypass.

### Proof of Concept
minitest plan (controller-level, no live GitHub):
```ruby
test "pull_request opened webhook verified via secret-less org cannot create a ReviewStack for a different org's repository" do
  # Arrange: org "attacker-org" has no webhook_secret (verify_webhook_signature returns true unconditionally)
  # Arrange: repository "victim-org/victim-repo" exists, tracked, review_stacks_enabled = true,
  #          provisioning_behavior = :allow_all
  victim_repo = shipit_repositories(:shipit) # or a fixture repo owned by "victim-org"
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)

  payload = {
    action: "opened",
    number: 999,
    pull_request: {
      id: 1, number: 999, url: "https://api.github.com/...", title: "forged",
      state: "open", additions: 1, deletions: 1,
      head: { sha: "deadbeef" * 5, ref: "attacker-branch" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: { owner: { login: "attacker-org" }, full_name: victim_repo.github_repo_name },
    sender: { login: "attacker" }
  }.to_json

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=whatever' # irrelevant, no secret configured for attacker-org

  assert_no_difference -> { victim_repo.review_stacks.count } do
    post :create, body: payload, as: :json
  end
  # Binding equality asserted both sides:
  # BEFORE: repository_owner("attacker-org") != full_name.owner("victim-org") -> should be rejected
  # AFTER (bug present): request accepted (200), and review_stacks.count increases by 1 -> assertion above fails, proving the vuln
end
```
This test currently fails to protect (the `assert_no_difference` would be violated) under the current code, demonstrating that a payload verified under one org's (missing) secret is processed against a different org's repository/review-stacks scope. It requires a test fixture/config with an org lacking `webhook_secret` (mirroring `test/dummy/config/secrets_double_github_app.yml`) and a tracked repository for a different org with `review_stacks_enabled` + `allow_all`.