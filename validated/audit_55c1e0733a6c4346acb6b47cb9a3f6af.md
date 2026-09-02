This confirms the confused-deputy pattern: `Shipit::Webhooks::Handlers::Handler#repository_name` (and every push/pull_request handler) reads `payload.dig('repository', 'full_name')` to select the target `Repository`/`Stack`, while `WebhooksController#verify_signature` selects which org's HMAC secret to check against using a *different* field, `payload.dig('repository', 'owner', 'login') || payload.dig('organization', 'login')`.### Title
Webhook signature verification is bound to the wrong payload field, letting an attacker who controls one configured GitHub organization forge push/pull_request events that act on another organization's repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC against using `repository_owner`, derived from `payload.dig('repository', 'owner', 'login')` (falling back to `payload.dig('organization', 'login')`). But every event handler that actually performs the write (sync/deploy/archive) looks up the target `Repository`/`Stack` using a *different* field of the same attacker-supplied JSON body: `payload.dig('repository', 'full_name')`. Because the raw body is attacker-crafted (not literally proxied from GitHub in a way that guarantees `repository.owner.login` and `repository.full_name` agree), these two fields can be set independently while the whole body is still correctly HMAC-signed with a secret the attacker legitimately possesses for their own configured organization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is: [2](#0-1) 

This chooses **which org's `webhook_secret`** is used to check the HMAC over the whole raw body. Meanwhile every default handler (`PushHandler`, all `PullRequest::*Handler`s) resolves the **actual repository/stack that gets acted on** using a separate field: [3](#0-2) [4](#0-3) 

Shipit explicitly supports multi-tenant configuration where several independent GitHub organizations are configured with their own `webhook_secret` in the same Shipit instance (`docs/setup.md`, "Using Multiple GitHub Applications"): [5](#0-4) 

An entity that is a legitimate admin of **one** of these configured organizations (call it OrgA) knows OrgA's `webhook_secret` (they configured it) and can therefore compute a valid `X-Hub-Signature` for **any** JSON body of their choosing. They can build a body where:
- `repository.owner.login` = `"OrgA"` (or `organization.login` = `"OrgA"` for org-scoped events) — satisfies `verify_signature`'s org/secret lookup.
- `repository.full_name` = `"OrgB/victim-repo"` — an entirely different, victim organization's repository tracked by the same Shipit instance.

Because the equality the code relies on — *"the organization whose secret validated this signature" == "the organization/repository the handler will act on"* — is never actually checked (only the first field feeds signature selection, only the second feeds the action), the binding breaks. This is the same root-cause pattern as the referenced Solidity report: a single accounting/trust value (`self.queue.fulfilled`, here "the org that is cryptographically bound to this request") is conflated with a related-but-distinct value (`toFulfill`, here "the org/repo that is actually operated on") instead of being consistently tied together.

### Impact Explanation
With a validly-signed (by their own org's secret) but internally inconsistent payload, an attacker who administers OrgA in a multi-org Shipit deployment can:
- Forge `push` events causing `PushHandler#process` to call `stack.sync_github(expected_head_sha: ...)` on Stacks belonging to OrgB's repository, forcing GitHub sync operations against an org they do not control.
- Forge `pull_request` events (`opened`, `closed`, `reopened`, `labeled`, `unlabeled`) to archive/unarchive review stacks or trigger provisioning workflows (`ReviewStackAdapter#find_or_create!`) on OrgB's repositories, since these handlers likewise resolve the repository from `params.repository.full_name` independent of the org used for signature validation.
- For org-scoped `membership` events, `MembershipHandler` uses `params.organization.login` to create/attach `Team` records and add/remove `User` memberships; if that field can be decoupled from the signature-selection field in the same way, team membership (which gates `User#authorized?` and thus application-wide authentication via `Shipit.github_teams`) could be manipulated cross-tenant.

This crosses the "cross-repository writes" / "unauthorized deploy triggering" bar for High/Critical impact: the write (sync, archive/unarchive, provisioning) happens on a repository/organization that never authenticated the request that authorized it. It does not require the victim org's `webhook_secret`, `private_key`, session, or `ApiClient` token — only credentials/knowledge the attacker legitimately possesses for a different, unrelated organization hosted on the same shared Shipit instance.

### Likelihood Explanation
Requires (a) a multi-org Shipit deployment (explicitly documented and supported as a first-class configuration), and (b) the attacker being a legitimate admin/holder of one configured org's `webhook_secret` (not the victim's). Given that `docs/setup.md` documents this exact multi-org topology as a supported feature, and no code anywhere cross-checks that `repository.owner.login`/`organization.login` matches `repository.full_name`'s owner segment, the precondition is realistic in any shared/multi-tenant Shipit installation.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner` and verifying the signature, also verify that the organization used for signature selection matches the owner segment of every `repository.full_name` (and `organization.login`) referenced by the payload before dispatching to handlers - i.e., enforce the invariant `repository_owner == repository.full_name.split('/').first` (case-insensitively) for repository-scoped events, and reject (422) on mismatch. Alternatively, have each `Handler` receive and validate the authenticated organization explicitly rather than trusting the payload's `repository.full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `docs/setup.md`'s multi-org example), both organizations having stacks tracked by the same Shipit instance.
2. As the admin of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and `POST` it to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret.
5. `PushHandler#process` calls `Handler#stacks`, which resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and invokes `stack.sync_github(expected_head_sha: ...)` on `OrgB`'s stacks — a write triggered on an organization/repository that never authenticated this request.

Note: I was unable to fully trace `Stack#sync_github`/`GithubSyncJob` internals in this pass to confirm exactly how far the downstream effects propagate (e.g., whether it can be chained into an actual deploy trigger) or to inspect `GithubHook` model scoping that some tests reference (`GithubHook::Organization`/`GithubHook::Repo`), which may add an additional authorization layer not fully explored here; a Devin session with full repository access would be needed to verify whether any such secondary check mitigates this at the handler level.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** docs/setup.md (L182-184)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.
```
