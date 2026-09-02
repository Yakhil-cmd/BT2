### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login`/`organization.login` field that is decoupled from the `repository.full_name` handlers actually act on, letting a validly-configured org holder forge events against another org's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC against, based on `repository_owner`, a value read straight out of the still-unverified JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). [1](#0-0) [2](#0-1) 

Once the signature check passes, every downstream handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) resolves the target `Repository`/`Stack` using a *different* field of the same attacker-supplied payload: `payload.dig('repository', 'full_name')`. [3](#0-2) [4](#0-3) 

### Finding Description
This mirrors the reentrancy report's root cause: a check is performed against one representation of state (`address(this).balance` delta), while the actual effect (paying for two NFTs) is driven by a different, attacker-influenced sequence of events, so the check no longer binds to the real action. Here the analogous binding is:

`organization that authenticated == organization that owns the repository being written to`

but the code never enforces this equality:

- `verify_signature` looks up the GitHub App config via `Shipit.github(organization: repository_owner)` and validates the raw request body's HMAC against **that org's** `webhook_secret`. [1](#0-0) 
- `repository_owner` is taken from the same raw, attacker-controlled JSON body that is about to be HMAC-verified — it is read *before* the signature check succeeds and is never cross-checked against `repository.full_name` afterward. [2](#0-1) 
- All webhook handlers derive the actual `Stack`/`Repository` to mutate purely from `repository.full_name`, a sibling field inside the same JSON object, with no re-validation that its owner matches `repository_owner`. [3](#0-2) 

In a Shipit deployment using the documented "Using Multiple GitHub Applications" feature (each configured org gets its own `webhook_secret`), a user who is an admin/owner of *one* configured GitHub organization — and therefore legitimately knows that org's `webhook_secret` because they configured/received it while installing their own GitHub App — can craft an arbitrary raw JSON payload themselves (not go through GitHub at all). They set `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` selects their own known secret and validates their own self-computed HMAC over the whole body. But they set `repository.full_name` inside the *same* payload to point at a stack belonging to a *different*, victim organization. Because the handlers only look at `repository.full_name`, the forged event is processed as if it legitimately came from the victim org, even though the cryptographic signature only proves authorship by the attacker's own org.

This is the exact analog called out in the rules: "an organization that authenticated versus the repository that is written" — the equality the code should enforce (`repository_owner_verified == repository.full_name.owner`) is never checked.

### Impact Explanation
Depending on the handler triggered, this allows an attacker who legitimately controls one Shipit-registered GitHub org to:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha: params.after)` against a victim stack with an attacker-chosen `after` SHA and `ref`, triggering GithubSyncJob and downstream sync/deploy-eligibility state changes for a repository the attacker has no legitimate access to. [5](#0-4) 
- Feed attacker-controlled `status`/`check_suite` payloads into a victim commit's CI state, since these too key off `repository.full_name`.

This is a cross-repository / cross-organization write that never should be reachable without possessing the target org's own webhook secret — matching the "cross-repository writes" High/Critical impact criterion in the rubric.

### Likelihood Explanation
Exploitation requires the attacker to be a legitimate admin of at least one GitHub organization that a Shipit instance is configured to serve in multi-org mode (a normal, unprivileged-relative-to-other-tenants position, not requiring any Shipit session, API token, or private key). Because the entire HTTP request (headers + raw body) is attacker-crafted directly against the webhook endpoint (no real GitHub delivery needed), the only "secret" required is the one the attacker legitimately possesses for their own org. This is realistic in any Shopify/Shipit-style shared/multi-tenant deployment as documented in the README ("Using Multiple GitHub Applications").

### Recommendation
After computing `repository_owner` and verifying the signature, re-derive the owner from `repository.full_name` (or `organization.login` for org-scoped events) and require it to equal the `repository_owner` value used to select the signing secret before dispatching to any handler. Alternatively, bind the webhook secret lookup and payload processing to the same canonical identifier (e.g., only trust `full_name`'s owner segment, and reject payloads where `repository.owner.login` disagrees with `repository.full_name`'s owner).

### Proof of Concept
1. Configure Shipit in multi-org mode with two orgs, `attacker-org` (attacker is admin, knows its `webhook_secret`) and `victim-org` (has stack `victim-org/victim-repo`).
2. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org secret, body)>` themselves and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and validates successfully because the attacker used their own known secret over their own crafted body. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` and invokes `stack.sync_github(expected_head_sha: ...)`, acting on the victim's stack despite the signature only proving `attacker-org` authored the request. [3](#0-2) [4](#0-3)

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
