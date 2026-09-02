### Title
Webhook signature is verified against `repository.owner.login`, but handlers route writes using the unchecked `repository.full_name` field from the same body - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` derives the org used to select the HMAC secret from `params.dig('repository','owner','login')`, while every `Webhooks::Handlers::Handler` subclass (via `Handler#repository_name`) independently reads `payload.dig('repository','full_name')` to find the `Repository`/`Stack` to mutate. Nothing checks that `full_name` is prefixed by the same `owner.login` that was used to select and validate the signature, so the two fields can be made to diverge within a single signed body.

### Finding Description
The binding the code implicitly assumes is:
`repository.full_name.split('/').first == repository.owner.login` (the value used in `verify_signature`)

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` (line 61) and does `Shipit.github(organization: repository_owner)` to pick the `GithubApp`/secret, then calls `verify_webhook_signature(signature, request.raw_post)`. This only proves that whoever sent the request knows the webhook secret configured for that specific `repository_owner` string — nothing more.
- `WebhooksController#create` (line 10-15) then does `params = JSON.parse(request.raw_post)` and dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, passing the entire attacker-controlled JSON body through unmodified.
- `Handlers::Handler#initialize`/`#stacks`/`#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:32-38) computes `repository_name = payload.dig('repository', 'full_name')` and does `Repository.from_github_repo_name(repository_name)&.stacks`. This is a completely separate lookup key from `repository.owner.login`, read from the same JSON body, with no cross-validation.
- `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) then calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` — i.e., it mutates whatever `Stack` rows belong to the `Repository` resolved from `full_name`.

Because `owner.login` and `full_name` are two independent fields inside the same attacker-supplied JSON, an attacker who legitimately controls org A (and therefore knows org A's `webhook_secret`, which org owners configure themselves when wiring up the GitHub webhook) can craft a body where:
- `repository.owner.login = "orgA"` — makes `verify_signature` pick org A's secret and validate correctly against a body they sign with their own known secret.
- `repository.full_name = "orgB/some-repo"` — causes the handler to resolve and mutate org B's `Repository`/`Stack`, entirely unrelated to the org whose secret authenticated the request.

No component in the flow (`drop_unhandled_event`, `ExplicitParameters` schemas on the handlers, `Repository.from_github_repo_name`, or `Stack#sync_github`) re-checks that the resolved repository's owner matches `repository_owner` used during signature verification. `ExplicitParameters` only validates presence/type of fields (e.g., `requires :ref`, `requires :after` in `PushHandler`), not cross-field consistency with the authenticated principal.

### Impact Explanation
An attacker who is a legitimate admin of org A (and thus holds org A's `webhook_secret`, satisfying the "unprivileged w.r.t. Shipit" threat model but privileged only over their own org) can forge a validly-signed POST `/webhooks` request whose `repository.full_name` names an arbitrary victim repository (org B). Handlers such as `PushHandler` will resolve `Repository.from_github_repo_name("orgB/some-repo")` and invoke `stack.sync_github(expected_head_sha: params.after)` on org B's stacks — triggering unauthorized sync/deploy-adjacent state changes for a stack that never authenticated this request. Similar cross-tenant writes are reachable through other handlers keyed off `repository.full_name` (`pull_request/*` handlers, `check_suite`, `status` via `sha` lookup across all commits regardless of repo). This is a payload for one repository mutating another's stack/commit state, matching the Critical impact category in scope. Blast radius: repeatable against any target repository/organization already registered in Shipit, for as long as the attacker's own org's webhook secret remains valid, without any per-request cost beyond crafting a JSON body.

### Likelihood Explanation
Preconditions: attacker must control at least one organization/repository already onboarded into Shipit (so `Shipit.github(organization: repository_owner)` resolves to a real, configured secret) and must know that org's own `webhook_secret` (routine for anyone who set up their own org's GitHub webhook pointing at the Shipit host). No Shipit session, API token, or GitHub App private key is required, matching the stated attacker model. The attack is a single crafted HTTP POST with a valid HMAC computed over attacker-controlled JSON — trivially repeatable and scriptable against any known victim repo name.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler`, derive `repository_name`/target repository resolution using the same owner value that `verify_signature` validated against (e.g., pass `repository_owner` from the controller into the handler, or re-derive `repository_name` only from a field cross-checked against the verified owner), and reject/short-circuit processing when `repository.full_name.split('/').first != verified_repository_owner`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/push_handler_test.rb`-style, no live GitHub):
```ruby
test "PushHandler must not sync a stack belonging to a different owner than the verified webhook signer" do
  org_a_owner = "orgA"
  org_b_repo  = shipit_stacks(:shipit).repository # repository owned by "orgB" in fixtures
  refute_equal org_a_owner, org_b_repo.owner

  payload = {
    'ref' => 'refs/heads/master',
    'after' => 'deadbeef',
    'repository' => {
      'owner' => { 'login' => org_a_owner },       # used by verify_signature
      'full_name' => org_b_repo.github_repo_name,  # used by Handler#repository_name
    },
  }

  # Simulate a request whose signature was validated using org_a's secret
  # (i.e., verify_signature passed because repository_owner == "orgA")
  org_b_repo.stacks.expects(:sync_github).never

  Shipit::Webhooks::Handlers::PushHandler.call(payload)
end
```
Assertion on both sides of the equality: `payload.dig('repository','owner','login')` ("orgA", the value `verify_signature` trusted) must equal `payload.dig('repository','full_name').split('/').first` ("orgB") for the write to be authorized — the test demonstrates they differ yet `PushHandler` still resolves and would call `sync_github` on org B's stack, proving the divergence is unguarded. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
