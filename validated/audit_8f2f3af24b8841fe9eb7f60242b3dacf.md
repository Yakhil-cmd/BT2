### Title
Webhook `X-Hub-Signature` verification keys off attacker-controlled `repository.owner.login`/`organization.login`, decoupling the authenticating organization's secret from the repository actually acted on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, which is read directly out of the *unverified* JSON body before the signature check occurs: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

After the signature is verified, the payload is dispatched unchanged to handlers, which locate the target `Stack`/`Repository` using a *different* field of the same untrusted payload — `repository.full_name` — via `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the repository that gets written to) are two independent, attacker-controlled JSON fields inside the same request body; nothing enforces that `full_name` starts with `owner.login`. Because `Shipit.github(organization:)` looks up a *per-organization* `webhook_secret` from `secrets.github[org]` (multi-org config, see `lib/shipit.rb:170-200`), an attacker who legitimately controls the webhook secret for **Org A** (e.g. they administer Org A's GitHub App/webhook settings in a multi-tenant Shipit instance) can forge a payload where:
- `repository.owner.login = "OrgA"` → causes `verify_signature` to check the HMAC against Org A's `webhook_secret`, which the attacker knows and can sign correctly, and
- `repository.full_name = "OrgB/some-repo"` → causes the dispatched handler (`PushHandler`, `StatusHandler`, pull-request handlers, etc.) to act on Stacks belonging to an entirely different organization/repository (Org B), which the attacker does not control.

This is the direct analog of the DODO bug: a verification/index key (`repository_owner`, "the token slot checked") is not bound to the value actually consumed for the write (`repository.full_name`, "the token slot acted on"), letting one authenticated identity's credential authorize operations on a different, unrelated resource — matching the rule's listed pattern "an organization that authenticated versus the repository that is written."

### Impact Explanation
Handlers dispatched with the forged, cross-org payload can trigger unauthorized state changes on Org B's stacks with no involvement from Org B: e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha:)` [4](#0-3) , and `StatusHandler#process` writes fabricated CI statuses onto arbitrary commits by sha, which can flip a commit's `deployable?` state and unblock deploys [5](#0-4) . This satisfies the "cross-repository writes" / "unauthorized deploy" Critical-impact bar, since the attacker never needed a Shipit session, an `ApiClient` token, or Org B's actual `webhook_secret` — only Org A's.

### Likelihood Explanation
This requires the deployment to be configured with the multi-organization GitHub config schema (`secrets.github[org]`), and for the attacker to legitimately hold a webhook secret for at least one configured organization (e.g. they are an admin of that org's GitHub App installation) while wanting to affect stacks of another org on the same Shipit instance. That is a realistic scenario for shared/multi-tenant Shipit deployments serving several GitHub organizations, and requires no privileged Shipit credentials — only crafting an HTTP POST with a valid HMAC for a secret the attacker legitimately possesses.

### Recommendation
After signature verification succeeds for `repository_owner`, cross-check that the same organization owns the resource the handler will act on before dispatching — e.g. verify `payload.dig('repository', 'full_name')` (or `organization.login` for org-scoped events) is prefixed by/consistent with the verified `repository_owner`, and reject (422) otherwise. Alternatively, resolve the target `Repository`/`Stack` first and confirm its owner organization matches the organization whose secret validated the signature before invoking any handler.

### Proof of Concept
1. Configure Shipit with multi-org GitHub config: `secrets.github = { orga: { webhook_secret: "secretA", ... }, orgb: { webhook_secret: "secretB", ... } }`, and Stacks exist for repository `orgb/target-repo`.
2. As an attacker who administers Org A's GitHub App (and thus knows `secretA`), craft a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POST to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "orga")` and successfully verifies the signature with `secretA`.
5. `Shipit::Webhooks.for_event('push')` dispatches `PushHandler.call(params)`, which resolves `Repository.from_github_repo_name("orgb/target-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on Org B's stack — a write the attacker was never authorized to make.

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
