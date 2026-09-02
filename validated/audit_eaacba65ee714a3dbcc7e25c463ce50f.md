### Title
Webhook signing-key selection uses `repository.owner.login` while payload processing acts on `repository.full_name`, allowing cross-repository/cross-stack writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
Analogous to the CErc721 `_seize` bug (a value used for one purpose — the rounding/authorization decision — is disconnected from the value that actually determines what gets acted upon), Shipit's webhook pipeline picks the HMAC secret used to *authenticate* a webhook based on one field of the payload (`repository.owner.login` / `organization.login`), but the handlers that *act* on the payload (creating syncs, statuses, deploy triggers) key off a different field (`repository.full_name`). Because the whole raw JSON body is attacker-controlled up to the point of signature validation, these two fields can be made inconsistent, breaking the binding `{org that authenticated} == {repository that gets written}`.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the signature against using only the owner field: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Once the signature is accepted, the *entire* raw payload — including the `repository.full_name` field, which was never part of the org-selection logic — is passed unchanged to the registered handler: [3](#0-2) 

Every handler (e.g. `PushHandler`) resolves which `Stack`/`Repository` to operate on via `Handler#repository_name`, which reads a *different* field of the same payload: [4](#0-3) [5](#0-4) 

Shipit explicitly supports multiple GitHub organizations, each with its own configured `webhook_secret` (`lib/shipit/github_app.rb` reads `@config[:webhook_secret]` per-organization instance, and `Shipit.github(organization: repository_owner)` looks the org up by name, raising `GithubOrganizationUnknown` if not found): [6](#0-5) 

Since the JSON body is fully attacker-supplied (an HTTP POST to `/webhooks` — there is no requirement that `repository.owner.login` and `repository.full_name` refer to the same repository), an actor who legitimately controls the webhook secret for **any one** organization configured on the Shipit instance can craft a payload where:
- `repository.owner.login` = their own org (so `verify_signature` picks the secret they know and the HMAC check passes), while
- `repository.full_name` = `"victim-org/victim-repo"` (an arbitrary repository/stack already tracked by the same Shipit instance, potentially owned by a completely different organization).

The equality the system is supposed to enforce — `organization whose secret authenticated the request == repository that is written by the handler` — is broken.

### Impact Explanation
With `PushHandler`, this lets the attacker enqueue `stack.sync_github(expected_head_sha: params.after)` against a stack that belongs to a repository/org they do not control, feeding an attacker-chosen `after` SHA as the `expected_head_sha` for that victim stack. This can desynchronize the victim stack's known commit state, trigger unwarranted GitHub syncs, and — for stacks with continuous deployment enabled — could feed into deploy triggering logic downstream, resulting in an unauthorized deploy/cross-repository write driven entirely by another organization's credentials. Other handlers (`StatusHandler`, `MembershipHandler`, `pull_request/*`) are similarly reachable with attacker-controlled content once past signature verification, since none of them re-validate that `repository.full_name`/`organization.login` used by the handler matches `repository_owner` used for authentication. This maps to the report's "High" impact class: an authorization/authentication decision made on one field but exploited via divergent state controlled through another field of the same trust-checked object.

### Likelihood Explanation
This requires the Shipit deployment to be configured for multiple GitHub organizations (an explicitly supported, documented feature — see `docs/setup.md` and the `config/secrets.*.yml` multi-org example) and requires the attacker to already know a `webhook_secret` for at least one of the organizations tracked by that instance (e.g., they are the person who configured that org's GitHub App integration, or that secret otherwise leaked to them). Given that assumption, forging the payload is trivial (this is a public, unauthenticated HTTP endpoint that only checks the raw body's HMAC, not internal field consistency) and requires no Shipit session, API token, or GitHub repository write access to the victim repo. I was unable to fully trace `GithubSyncJob`/`Stack#sync_github` internals within the remaining tool budget to confirm the exact downstream consequence chain (e.g., whether an unauthorized deploy is directly triggerable versus only a corrupted sync state); this should be verified further.

### Recommendation
After successfully verifying the webhook signature for the organization identified by `repository_owner`, re-validate that every organization/repository-identifying field used later by handlers (`repository.full_name`'s owner segment, `organization.login`, etc.) is consistent with `repository_owner`. Reject the webhook (422) if there is any mismatch, so the authenticated organization and the repository actually acted upon are cryptographically and logically the same entity.

### Proof of Concept
1. Configure (or gain knowledge of) the `webhook_secret` for organization `attacker-org`, which is one of several organizations configured in this Shipit instance's `secrets.yml`.
2. Craft a JSON push-event payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over the exact raw JSON body.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully using the attacker's own secret (`app/controllers/shipit/webhooks_controller.rb` lines 24-30).
6. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb` lines 12-17) resolves `stacks` via `repository_name` = `"victim-org/victim-repo"` (`handler.rb` lines 32-38), and triggers `sync_github(expected_head_sha: "deadbeef...")` on stacks belonging to `victim-org`, despite the request never being authenticated by `victim-org`'s own webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```
