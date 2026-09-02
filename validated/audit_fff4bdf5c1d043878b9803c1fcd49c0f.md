### Title
Webhook signature verified against `repository.owner.login` while stack lookup trusts `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The external report describes a class of bug where one field of an attacker-influenced payload is used for a security decision (which app/binary to launch) while a *different, unchecked* field of the same payload actually determines what gets executed (`shell.openExternal(link)` picking up `file://…`/`smb://…`). The same "checked-field vs acted-upon-field" split exists in Shipit's GitHub webhook pipeline: `WebhooksController#verify_signature` selects the HMAC secret to validate against using `repository.owner.login` (or `organization.login`) from the JSON body, but the handlers that actually mutate state (`Shipit::Webhooks::Handlers::Handler#stacks`, and every `PullRequest::*Handler`) resolve the target `Repository`/`Stack` using the unrelated `repository.full_name` field from that same body.

### Finding Description
`WebhooksController#verify_signature` computes which GitHub App/secret to check the `X-Hub-Signature` against like this: [1](#0-0) 
using [2](#0-1) 

That is, the *authentication binding* is: `Shipit.github(organization: params.dig('repository','owner','login'))`'s secret ⇔ signature over the raw body.

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers such as `PushHandler`, `PullRequest::OpenedHandler`, `PullRequest::ClosedHandler`, `PullRequest::LabeledHandler`, etc. Every one of these resolves the repository/stack to act on via `params.repository.full_name`, not `repository.owner.login`: [3](#0-2) [4](#0-3) 

Nothing in the code cross-checks that the `owner.login` used for signature verification actually matches the `owner` portion of `repository.full_name` used for the write. Since GitHub webhook secrets are configured per-organization (`Shipit.github(organization: ...)`, see `docs/setup.md` and `lib/shipit.rb`), an attacker who legitimately controls (or has push access to) a repository in *organization A* — and therefore knows organization A's webhook secret because they can trigger and observe real webhook deliveries, or otherwise obtains a validly-signed payload for org A — can craft a payload whose `repository.owner.login`/`organization.login` is `A` (so `verify_signature` picks org A's correct secret and the HMAC matches) while `repository.full_name` is set to `B/some-other-repo`, a completely unrelated stack tracked by Shipit under a different organization/App installation.

Because `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` for the matched stack, and the `PullRequest::*Handler`s create/archive/unarchive `ReviewStack`s, provision infrastructure, and update pull-request/label state for whatever stack is looked up under `full_name`, this lets the request forge state changes against a stack belonging to a repository/org the attacker was never authorized against by the corresponding installation's secret.

### Impact Explanation
This breaks the binding "the organization that authenticated (secret used to verify HMAC) == the repository that is written (stack resolved and mutated by the handler)." Depending on the handler reached, an attacker holding a valid webhook secret for *one* organization/repository can trigger `GithubSyncJob`/`sync_github` (re-sync from GitHub, potentially altering deploy_spec caching and commit backlog), or force-create/archive/unarchive review stacks (deprovision/reprovision infrastructure) for a stack belonging to an entirely different, unrelated repository. This is a cross-repository write achieved purely by control over the attacker's own organization's webhook secret, matching the "cross-repository writes" Critical-impact bucket.

### Likelihood Explanation
Exploitation requires the attacker to be able to produce a validly HMAC-signed payload for at least one organization configured in Shipit (e.g., because they administer a GitHub App installation/webhook for their own org, or otherwise have `github.webhook_secret` for that org) — this is a much lower bar than requiring a Shipit session, an `ApiClient` token, or repository write access to the *target* repository. The webhook endpoint is unauthenticated by design (relies purely on the HMAC check), and the mismatch between the field used for verification and the field used for the actual write is not defended against anywhere in `WebhooksController` or `Shipit::Webhooks::Handlers::Handler`.

### Recommendation
In `WebhooksController#verify_signature`, after establishing which organization's secret validated the signature, also verify that `params.dig('repository','owner','login')` (the value used to select the secret) matches the owner segment of `params.dig('repository','full_name')` before dispatching to handlers. Alternatively, have `Shipit::Webhooks::Handlers::Handler#repository_name` derive the repository strictly from the same trusted identity used for signature verification rather than trusting `repository.full_name` independently. Reject the request (422) on mismatch.

### Proof of Concept
1. Attacker controls organization `attacker-org` in GitHub and has configured/observes its Shipit webhook secret `S_attacker`.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, raw_body)` and sets header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (it was computed with `S_attacker`).
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack, even though the request was never signed by `victim-org`'s installation secret.

Note: I was unable to fully confirm end-to-end impact severity (e.g., whether `sync_github`/review-stack provisioning alone rises to "unauthorized deploy" strength) purely from the indexed code; a background Devin session with full repo/test access would be needed to trace `sync_github`'s downstream effects (e.g., whether it can trigger `CacheDeploySpecJob`/deploys) to fully corroborate the Critical vs High severity classification.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
