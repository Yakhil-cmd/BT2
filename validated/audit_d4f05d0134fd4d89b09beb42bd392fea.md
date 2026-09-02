### Title
Webhook signature scoped to attacker's own GitHub organization allows forging CI status for any commit, enabling unauthorized deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using a field taken from the same unauthenticated JSON body (`repository.owner.login`), rather than binding validity to the specific repository/commit the handler subsequently mutates. `StatusHandler#process` then writes a `Status` record by looking up `Commit.where(sha: params.sha)` globally, with no check that the sha belongs to a repository owned by the organization whose secret validated the signature. An attacker who legitimately controls (and has configured) any organization on this multi-tenant Shipit instance can therefore forge a signed `status` webhook that is verified against their *own* org's secret but whose payload references a commit sha belonging to a completely different, victim organization/stack.

### Finding Description
`Shipit::WebhooksController#verify_signature` resolves the GitHub App/secret to check against with: [1](#0-0) 
where `repository_owner` is read straight out of the untrusted request body: [2](#0-1) 

Because this instance can be configured with multiple independent GitHub organizations (see the multi-org config shape), each with its own `webhook_secret`: [3](#0-2) 

an attacker who administers Organization A (and therefore legitimately knows/controls A's `webhook_secret`) can compute a valid `X-Hub-Signature` for an arbitrary JSON body as long as `repository.owner.login` in that body is set to `"A"`. The signature check only proves "org A signed this exact byte string" — it does not constrain what other fields (like `sha`) inside that same signed body may reference.

`StatusHandler#process` then acts on the payload with no repository/organization scoping at all: [4](#0-3) 

It queries `Commit.where(sha: params.sha)` across the entire installation and calls `create_status_from_github!(params)`, writing an arbitrary `state`/`context`/`description` for any commit already known to Shipit — including commits belonging to Organization B's stacks that A has no access to. Contrast this with the base `Handler` class, which *does* provide repository-scoped lookup via `repository_name`/`stacks` used by `PushHandler` and the pull-request handlers: [5](#0-4) 
`StatusHandler` bypasses this scoping entirely.

The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login) == organization owning the repository/commit written by the handler (sha's stack/repository)`

Before the attack: only genuine webhooks from GitHub for org X can write CI status for org X's commits. After a forged request from org A referencing org B's commit sha: a `Status` row is created/updated for org B's commit with attacker-chosen `state`, e.g. `"success"`, and attacker-chosen `context`.

`Commit#deployable?` uses exactly this data to gate deploys: [6](#0-5) 

So a victim's commit that never actually passed CI can be flipped to "deployable" purely from a webhook signed with an unrelated organization's secret.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written." Falsifying the CI status of a commit that a legitimate stack maintainer would otherwise reject or refuse to deploy lets that (unwitting, authorized) maintainer trigger an "unauthorized deploy" of a build that never satisfied its required CI checks — one of the explicitly listed Critical/High impacts. It also affects merge-queue safety checks that rely on the same `Status`/`required_statuses` mechanism (`MergeRequest#reject_unless_mergeable!`), potentially causing an unsafe automatic merge.

### Likelihood Explanation
The attacker needs no Shipit session, `ApiClient` token, `webhook_secret` of the victim org, or GitHub write access to the victim repository — only administrative control of *any* GitHub organization configured on the same multi-tenant Shipit instance (a realistic deployment shape, as shown by the multi-org secrets config), plus knowledge of a target commit's SHA (public/visible information, not secret). `StatusHandler` performs zero cross-checking between the authenticating organization and the commit being mutated, making exploitation straightforward once those two low-bar prerequisites are met.

### Recommendation
- In `StatusHandler` (and any other handler that doesn't already use `Handler#stacks`), scope the `Commit` lookup to stacks belonging to the repository named in the payload, and additionally verify that the repository's owner matches the organization whose secret validated the signature.
- In `WebhooksController#verify_signature`, after selecting the secret for `repository_owner`, cross-validate that `repository.full_name`'s owner segment equals `repository.owner.login`/`organization.login`, rejecting mismatched payloads.
- Consider deriving the signing organization from a source that cannot be pointed at another tenant (e.g. require the GitHub App installation id in-app-configured per org, not a body field), or maintain a strict per-organization repository allow-list checked before any DB mutation in every handler.

### Proof of Concept
1. Shipit is configured (per `config/secrets*.yml`) with two organizations, `victim-org` and `attacker-org`, each with its own `webhook_secret`.
2. Attacker legitimately administers `attacker-org` and thus knows `attacker-org`'s `webhook_secret`.
3. Attacker obtains the SHA of a commit in `victim-org`'s tracked repository/stack (public information, e.g. visible on GitHub or in the Shipit UI) that currently fails or lacks required CI (`ci.require`).
4. Attacker builds a JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-context",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/anything" }
}
```
5. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
6. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s secret, and the signature validates.
7. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `success` status for the victim's commit, independent of `attacker-org`/`victim-org` mismatch.
8. `Commit#deployable?` for that commit now returns `true`; any user with normal (legitimate) deploy permission on `victim-org`'s stack can deploy that commit through the ordinary UI, completing an unauthorized deploy enabled by the forged cross-organization status.

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
