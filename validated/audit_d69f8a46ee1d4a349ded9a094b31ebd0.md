## Title
Webhook organization selected for signature verification is never bound to the repository the handler writes to, allowing cross-repository/cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The reported "getEarnings() underflow" bug is a class of *state-binding inconsistency*: one field is used to authorize an action while a different, unchecked field is used to actually perform it. The same bug class exists in Shipit's webhook pipeline: the GitHub organization used to select the HMAC secret for signature verification is not the same value used afterward to determine which repository/stack the webhook payload is applied to.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify against using `repository_owner`, which is read straight out of the *unverified* JSON body: [1](#0-0) [2](#0-1) 

Once the signature validates against that organization's secret, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the raw payload, and every handler resolves the target stack from a *different* field, `repository.full_name`, again taken from the same unverified body: [3](#0-2) 

There is no code path that checks `repository.owner.login == repository.full_name.split('/').first` (or otherwise ties the two fields together). Because GitHub App webhook secrets are configured per-organization (see `config/secrets.*.yml` / `docs/setup.md` multi-org example), any party who legitimately knows one organization's `webhook_secret` (e.g. an admin of Org A's own GitHub App installation) can compute a valid HMAC over an arbitrary JSON body where `repository.owner.login = "OrgA"` (so the correct secret is selected and the signature checks out) while `repository.full_name = "OrgB/some-other-repo"`. The handler will then act on `OrgB/some-other-repo`'s stack, even though the cryptographic signature only ever authenticated "this request legitimately originates from someone who knows Org A's secret," not "this request legitimately concerns a repository owned by Org A."

This breaks the intended equality: `organization authenticated by verify_webhook_signature == organization owning the repository the handler mutates`. Handlers such as `PushHandler` (queues `GithubSyncJob`), `StatusHandler` (writes commit `Status` rows), and the `pull_request/*` handlers (merge/label/close pull requests) all trust `repository.full_name` unconditionally once the outer signature check passes.

### Impact Explanation
An attacker who controls (or compromises) the webhook secret of *any single* GitHub organization/App configured in a multi-org Shipit deployment (see `docs/setup.md` "Using Multiple Github Applications") can forge webhook deliveries that are processed as authentic for **any other tracked repository/stack**, regardless of organization. This can trigger unauthorized sync jobs, fabricate CI status updates that unblock deploy safety checks, or manipulate pull-request-driven merge queue state for repositories the attacker has no access to — i.e., a cross-repository write driven by a mismatched trust binding.

### Likelihood Explanation
Exploitability requires knowledge of a valid webhook secret for at least one organization configured in the Shipit instance — a low bar for an org admin of any tenant sharing a single Shipit deployment (a documented, supported configuration), and does not require a Shipit session, `ApiClient` token, or repository write access on GitHub itself.

### Recommendation
After signature verification, assert that `payload.dig('repository', 'owner', 'login')` (the field used to select the verifying secret) matches the owner segment of `payload.dig('repository', 'full_name')` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org example).
2. As someone who knows `OrgA`'s `webhook_secret` (e.g., an admin of `OrgA`'s GitHub App), craft a `push` payload:
   ```json
   { "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/secret-repo" }, "ref": "refs/heads/main", "after": "<attacker-chosen sha>" }
   ```
3. Sign it with `OrgA`'s secret: `X-Hub-Signature: sha1=<hmac>`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` selects `Shipit.github(organization: 'OrgA')` via `repository_owner`, and the signature check passes.
5. `PushHandler` resolves the stack via `repository.full_name` = `OrgB/secret-repo`, enqueuing a `GithubSyncJob` for a stack the attacker never authenticated against.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
