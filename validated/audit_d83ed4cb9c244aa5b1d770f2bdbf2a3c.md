### Title
Webhook signature verified against `repository.owner.login`'s org secret while stack creation trusts unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to authenticate a webhook via `params.dig('repository','owner','login')`, but `PullRequest::OpenedHandler#repository` resolves the target `Shipit::Repository` via `Repository.from_github_repo_name(params.repository.full_name)`, a completely separate field that is never cross-checked against the signing organization. In a multi-organization Shipit deployment, an org that owns its own legitimate `webhook_secret` can therefore forge a `pull_request` `opened` event whose `repository.full_name` names a repository belonging to a different, victim organization, causing a `ReviewStack`/`Stack` row to be created under the victim's tracked repository.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`org_that_signed_the_request (params.dig('repository','owner','login'), used in WebhooksController#repository_owner) == org_owning_the_Repository_that_receives_the_new_row (Repository.from_github_repo_name(params.repository.full_name).owner)`

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (line 59-62) reads only `params.dig('repository','owner','login')` (or `organization.login`). It verifies `X-Hub-Signature` against that org's `webhook_secret` via `GithubApp#verify_webhook_signature` [1](#0-0) . It never reads or validates `repository.full_name`.
- On success, `WebhooksController#create` dispatches the raw parsed JSON to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) , passing the full attacker-controlled payload, including `repository.full_name`, into the handler untouched.
- `PullRequest::OpenedHandler#repository` (app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54) resolves the repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`.
- `Repository.from_github_repo_name` (app/models/shipit/repository.rb:53-56) simply splits `full_name` on `/` and does `find_by(owner:, name:)` — a DB lookup keyed entirely by the string the attacker put in `repository.full_name`, with zero reference to `repository.owner.login` or to which org's secret verified the request.
- `OpenedHandler#process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` (line 41-46), and `ReviewStackAdapter#create!` does `scope.create!(stack_attributes)` (app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:72-90) — since `scope` is `repository.review_stacks` (an ActiveRecord association), the new `Stack`/`ReviewStack` row's `repository_id` is forcibly set to the victim repository resolved from `full_name`, independent of which org's `webhook_secret` verified the request.

No component in this path (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema in `OpenedHandler.params`, `Repository.from_github_repo_name`, or `ReviewStackAdapter`) ever asserts `repository.owner.login == full_name.split('/').first`. The `ExplicitParameters` schema only requires `repository.full_name` to be present as a `String` — it does not require/verify a matching `owner` field.

Attacker request: POST `/webhooks` with `X-Github-Event: pull_request`, `X-Hub-Signature` computed with `attacker-org`'s real `webhook_secret`, body containing `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, `action = "opened"`, and a valid `pull_request` object. `verify_signature` passes because it only checks the org named in `owner.login`. `OpenedHandler` then resolves the real victim `Repository` row by `full_name` and creates a `ReviewStack` under it.

### Impact Explanation
An attacker who is a legitimate owner/admin of one organization tracked by a multi-org Shipit instance can forge a `pull_request` webhook that creates arbitrary `Stack`/`ReviewStack` rows (with attacker-controlled `branch`, PR metadata, and provisioning) under any other tracked repository whose `review_stacks_enabled` and `provisioning_behavior_allow_all` are set, without ever possessing that victim org's `webhook_secret`. This is a cross-tenant write: a payload authenticated for one repository/org mutates another repository's/org's Stack table, and the resulting `ReviewStack` is queued for provisioning (`Shipit::ReviewStackProvisioningQueue.add(stack)`), potentially triggering deploy/provisioning tasks against the victim's infrastructure using the victim's own deploy pipeline. This matches the "payload for one repository mutating another's stack" Critical category. It is repeatable against any other tracked repository name known to the attacker (repo names are typically public/knowable), for every `pull_request` event, and similarly affects other handlers (`ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `Hook`'s general `stacks` lookup in `Handler#stacks`) that use the same `Repository.from_github_repo_name(payload.dig('repository','full_name'))` pattern.

### Likelihood Explanation
This requires: (1) Shipit configured with multiple GitHub organizations, each with its own `webhook_secret` (a supported, documented configuration — `docs/setup.md` "Using Multiple Github Applications"); (2) the attacker administers/owns one such organization (`attacker-org`) and therefore legitimately knows its own `webhook_secret`; (3) the victim repository is already tracked by Shipit with `review_stacks_enabled: true` and a permissive `provisioning_behavior`. Given these preconditions, the attack cost is a single crafted, self-signed HTTP POST — no GitHub session, Shipit login, or victim secret needed. It is fully repeatable and deterministic since the code path performs no cross-org ownership check.

### Recommendation
In `WebhooksController#verify_signature` (or in each `Handler`/`OpenedHandler#repository`/`Handler#stacks`), enforce that the organization used to verify the webhook signature matches the owner segment parsed from `repository.full_name` before resolving/mutating any `Repository`. E.g., after computing `repository_owner`, also derive `full_name_owner = params.dig('repository','full_name')&.split('/', 2)&.first` and reject (422) the request if `repository_owner.casecmp?(full_name_owner)` is false. Alternatively, have `Repository.from_github_repo_name` accept and require the verified organization and refuse a match when the row's `owner` differs from it.

### Proof of Concept
Add a minitest integration test to `test/controllers/webhooks_controller_test.rb` (conceptual plan, not written into `test/**` here per scope, but this is the mechanism to prove it):
1. Set up dummy secrets for two orgs, e.g., `attacker-org` and `victim-org` (via `test/dummy/config/secrets_double_github_app.yml`-style fixture), each with a distinct `webhook_secret`.
2. Create `shipit_repositories(:victim)` with `owner: "victim-org"`, `name: "victim-repo"`, `review_stacks_enabled: true`, `provisioning_behavior: "allow_all"`.
3. Build a `pull_request` "opened" JSON payload where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`.
4. Sign the raw JSON body with `attacker-org`'s `webhook_secret` (`sha1=` HMAC as done in `GithubApp#verify_webhook_signature`) and set it as `X-Hub-Signature`; set `X-Github-Event: pull_request`.
5. POST to `/webhooks` with that body/signature.
6. Assert `response).to be :ok` (signature accepted for attacker-org).
7. Assert `Shipit::ReviewStack.last.repository_id == shipit_repositories(:victim).id`, proving the org whose secret verified the request (`attacker-org`) differs from the org owning the mutated repository (`victim-org`), demonstrating the broken binding end-to-end with no live GitHub calls (stub `Shipit.github(organization: ...)`/`GithubApp#verify_webhook_signature` only where needed for determinism).

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```
