### Title
Webhook signature verification binds the wrong field of the payload, allowing a signature from one GitHub organization/App to authenticate events targeting another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted, attacker-supplied JSON body. However, the actual event handlers (e.g. `PushHandler`, `StatusHandler`, `Handler#repository_name`) resolve the target `Repository`/`Stack` using a *different* field of the same body: `repository.full_name`. Nothing ties these two fields together, so a webhook that is validly signed for organization A can carry a `repository.full_name` pointing at organization B's repository, and the handler will happily act on organization B's stack.

### Finding Description
`verify_signature` picks the app/secret purely from the payload: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

and: [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — a field read straight out of the JSON body, not out of any trusted/independent context. The HMAC is computed over `request.raw_post`, so the *body content* is authenticated as coming from whoever knows the secret for that organization — but the code equates "whoever knows org A's secret" with "authorized to act on any repository the body happens to mention."

The event handlers, however, use a completely separate field to decide *which* repository/stack to modify: [3](#0-2) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` splits `full_name` (`"owner/name"`) and looks up any repository record with a matching owner/name, regardless of which organization's secret validated the request: [4](#0-3) 

For a `push` event, `PushHandler.process` then triggers `stack.sync_github` for every not-archived stack on the matching branch: [5](#0-4) 

For a `status` event, `StatusHandler.process` looks up commits purely by `sha` (global, not repo-scoped) and creates a status record from **attacker-controlled** `state`/`description`/`target_url`/`context` fields: [6](#0-5) 

The binding that should hold is:
`organization whose secret validated the signature == owner of the repository the handler is about to mutate`

Instead the code enforces:
`organization used to select the verification key (payload.repository.owner.login) != owner encoded in payload.repository.full_name (used for the actual mutation)`

Nothing cross-checks that `repository.owner.login` matches the owner portion of `repository.full_name`. Both are attacker-controlled fields of the same unsigned-at-selection-time JSON body (the signature only proves the body wasn't tampered with by someone lacking org A's secret — it says nothing about consistency between fields inside that body).

### Impact Explanation
An attacker who legitimately controls (or has been granted) a Shipit-configured GitHub App/org — e.g. one org in a multi-org Shipit deployment (`config/secrets.development.shopify.yml` shows the multi-org shape with distinct `webhook_secret` per org) — knows that org's `webhook_secret`. They can craft and correctly sign an arbitrary webhook body where `repository.owner.login` = their own org (so `verify_signature` picks and successfully checks their own secret) while `repository.full_name` = `"victim-org/victim-repo"`.

This lets the attacker:
- Forge a `status` event with `state: "success"` for an arbitrary victim commit `sha`, creating a fabricated passing CI status on a repository they do not own — this is exactly the kind of check Shipit's deploy/safety gating relies on to decide whether a commit is safe to ship, so it can be used to make an otherwise-unreviewed/unsafe commit appear deployable, enabling an **unauthorized deploy** of a victim stack.
- Force `GithubSyncJob` to run against a victim stack with an attacker-chosen `expected_head_sha`, injecting sync activity into an org's stack that the attacker has no legitimate relationship with.

This meets the Critical bar of "unauthorized deploy" via cross-organization write to a stack the attacker's credentials should never reach.

### Likelihood Explanation
Requires the attacker to already control a legitimate, Shipit-registered GitHub App/organization (i.e. know that org's `webhook_secret`) but requires no access to the victim org, no Shipit session, and no `ApiClient` token — which is exactly the kind of "unprivileged relative to the victim" attacker this class of finding targets. Multi-tenant Shipit installs (multiple orgs sharing one instance, as documented/exemplified in `config/secrets.development.shopify.yml`) are the most directly affected, since the attacker-controlled org and the victim org coexist behind the same `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in each `Handler`), after signature verification, validate that the organization owner used to select the verifying secret (`repository_owner`) matches the owner encoded in `payload.dig('repository', 'full_name')` (and any other repository references used later, e.g. in `StatusHandler`/`PushHandler`). Reject the webhook (422) on mismatch. Ideally, bind repository resolution to the same trusted identifier used for signature selection rather than re-deriving it from a second, independently-controllable field of the same body.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (as supported by `Shipit.github(organization:)`).
2. Attacker knows `attacker-org`'s `webhook_secret` (it is their own GitHub App).
3. Attacker crafts a `status` event body:
```json
{
  "sha": "<victim-stack-current-commit-sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (derived from `repository.owner.login`) and successfully verifies the signature against the attacker's own secret.
6. `StatusHandler.process` runs and calls `Commit.where(sha: ...)`/`create_status_from_github!` unconditionally on any commit matching that SHA, without checking that the commit's stack belongs to `attacker-org` — creating a forged "success" status that can be leveraged toward an unauthorized deploy of `victim-org/victim-repo`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
