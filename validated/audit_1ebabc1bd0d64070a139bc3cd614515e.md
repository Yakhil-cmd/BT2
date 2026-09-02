### Title
Webhook organization-selection field is decoupled from the repository field the payload writes to, allowing cross-repository forgery when any configured GitHub org has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to validate the incoming payload against using `repository.owner.login` (falling back to `organization.login`), while every webhook `Handler` subsequently resolves the actual `Stack`/`Repository` to mutate using a completely different, unauthenticated field of the same payload: `repository.full_name`. `GitHubApp#verify_webhook_signature` additionally returns `true` unconditionally when the selected app's `webhook_secret` is blank. These two facts combine to let an attacker who only needs one org in the Shipit instance to be configured without a `webhook_secret` forge webhook payloads that act on any other org/repository/stack tracked by the instance.

### Finding Description
- `verify_signature` picks the signing organization from the payload itself: `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`, then does `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank for that organization's config: `return true unless webhook_secret`. [3](#0-2) 

- Every webhook `Handler` (push, pull_request, status, etc.) resolves the repository/stack to act on from a *different, independently-attacker-controlled* field of the same JSON body: `payload.dig('repository', 'full_name')`. [4](#0-3) 

- `PushHandler` calls `stack.sync_github` for every matching branch of the resolved repo, and `PullRequest::ClosedHandler` archives the resolved repo's review stack — i.e., real state-changing operations keyed off `repository.full_name`. [5](#0-4) [6](#0-5) 

Nothing in `WebhooksController` or `Handler` enforces that `repository.owner.login` (the field used to select the secret to verify against) actually matches the owner encoded in `repository.full_name` (the field used to select what gets written to). GitHub's own webhooks always keep these consistent, but the controller trusts the raw, unauthenticated JSON body for both — it never re-derives `repository.owner.login` from `full_name` or vice versa. Consequently, if the Shipit deployment is configured with more than one GitHub organization (as supported by `Shipit.github(organization:)` and exercised by `secrets_double_github_app.yml` in the test suite) and any one of those orgs is left with no `webhook_secret` — a state the codebase explicitly treats as valid ("If you've set a webhook secret ... you should copy it here", implying it is optional) — an unprivileged external attacker can:

1. Set `repository.owner.login` (or `organization.login`) to the org that has no `webhook_secret` configured, causing `verify_webhook_signature` to return `true` for any signature (or none).
2. Set `repository.full_name` to `"<victim-org>/<victim-repo>"`, a repository tracked by a *different*, properly-secured org in the same instance.
3. `WebhooksController#create` passes the whole forged `params` to `Shipit::Webhooks.for_event(event)` handlers, which resolve and mutate the victim stack via `repository_name`/`full_name`, entirely bypassing the victim org's real webhook secret.

This breaks exactly the trust binding: *the organization whose credentials were used to authenticate the request* ≠ *the repository whose state is written by the request*.

### Impact Explanation
This allows cross-repository writes without possessing the target repository's/organization's webhook secret, which is explicitly listed as a Critical impact ("cross-repository writes, or an unauthorized deploy, rollback or merge"). Concretely, an attacker can trigger `Stack#sync_github` (push handler) or archive/close review stacks / manipulate commit statuses for a repository they have no legitimate relationship to, as long as any other org in the same Shipit instance lacks a configured `webhook_secret`.

### Likelihood Explanation
Requires a specific but realistic and documented-as-optional misconfiguration: a multi-organization Shipit deployment where at least one configured GitHub org has no `webhook_secret` set (the setup docs describe `webhook_secret` as something you set only "if you've set a webhook secret during the App creation", i.e., optional, and `template.rb`'s generated config leaves it blank by default). Where this condition holds, exploitation requires no credentials, no session, and no API token — only knowledge of the low-secret org's name and the target repository's `full_name`, both of which are typically public information. Where every configured org enforces a secret, this specific path is not exploitable, but nothing in the engine prevents or warns against the vulnerable multi-org configuration.

### Recommendation
- In `Handler#repository_name` / `Handler#stacks`, cross-check that the resolved repository's owner matches the `repository_owner` (or `organization.login`) value that was actually used to select and verify the webhook signature; reject the payload if they diverge.
- In `GitHubApp#verify_webhook_signature`, stop treating a blank `webhook_secret` as an automatic pass; require an explicit, separate "authentication disabled" flag (mirroring `Shipit.authentication_disabled?` for user auth) instead of silently trusting unsigned payloads.
- Consider binding webhook secret verification directly to the specific `Repository`/`Stack` resolved by the handler rather than to an organization inferred from the unauthenticated payload.

### Proof of Concept
Preconditions: Shipit instance configured with two orgs, e.g. `low-secret-org` (no `webhook_secret`) and `victim-org` (properly secured, owning stack `victim-org/victim-repo` tracked in Shipit).

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "low-secret-org" }
  }
}
```

1. `WebhooksController#verify_signature` calls `Shipit.github(organization: "low-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (forged/omitted) `X-Hub-Signature` header. [3](#0-2) 
2. `WebhooksController#create` dispatches to `PushHandler`, whose `repository_name` resolves via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`. [7](#0-6) 
3. `PushHandler#process` finds `victim-org/victim-repo`'s stacks on branch `master` and invokes `stack.sync_github(expected_head_sha: ...)`, a real state-changing operation on a repository the attacker never authenticated against. [5](#0-4)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
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
```
