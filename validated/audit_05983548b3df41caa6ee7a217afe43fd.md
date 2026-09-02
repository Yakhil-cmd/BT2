### Title
Webhook signature verification keyed on `repository.owner.login` while the mutated repository is selected from the unverified `repository.full_name` field, allowing cross-tenant forgery of push syncs and commit statuses - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which per-organization `webhook_secret` to validate the inbound HMAC signature against using `repository_owner`, derived from the request body itself (`repository.owner.login` / `organization.login`). Once the signature is accepted, the *entire* raw payload — including the unrelated `repository.full_name` field — is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and `Handler#stacks` resolves the actual `Repository`/`Stack` to mutate from `repository.full_name`, a field never checked against `repository.owner.login`. Nothing enforces that the organization whose secret authenticated the request matches the repository whose data is written.

### Finding Description
Signature check:
```ruby
# app/controllers/shipit/webhooks_controller.rb:24-30
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```
```ruby
# app/controllers/shipit/webhooks_controller.rb:59-62
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

Handler dispatch and target resolution, using a *different* field of the same body:
```ruby
# app/models/shipit/webhooks/handlers/handler.rb:32-38
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

Shipit is designed to be configured for multiple GitHub organizations simultaneously (see `config/secrets.development.shopify.yml`, listing multiple orgs each with their own `webhook_secret`) and looks up the app config per-`organization`, raising `GithubOrganizationUnknown` only if the claimed owner login isn't configured at all.

The vulnerable binding is:
`organization authenticated (repository.owner.login used for HMAC secret selection)` **≠** `repository actually written (repository.full_name used for Stack/Repository lookup in the handler)`.

Because no code path cross-checks that `repository.full_name`'s owner segment equals `repository.owner.login`, a party that legitimately controls one organization configured in this Shipit instance (and therefore legitimately knows/derives a valid signature for their own `webhook_secret`) can craft a raw JSON body where `repository.owner.login` is their own org (so `verify_signature` succeeds) while `repository.full_name` names a *different* organization's repository/stack already tracked by the same Shipit instance. The handler then executes against that other org's `Stack`.

### Impact Explanation
`PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb) triggers `stack.sync_github(expected_head_sha: params.after)` on whichever stacks are returned by `stacks` — resolved purely from the attacker-controlled `repository.full_name`, not the authenticated org. Similarly, the `status` event handler writes a `Status` (state/context/description/target_url) for an arbitrary `sha` against the resolved repository/commit. Since Shipit gates deploys on required CI statuses (`ci.require` in `shipit.yml`), an attacker who is a legitimate tenant of one org on a shared Shipit deployment can forge a "success" CI status on a *different* tracked organization's commit, or force an out-of-band sync, without ever needing that victim organization's webhook secret, GitHub App key, or any Shipit session/API token. This is a cross-repository write across organizational trust boundaries and can lead to an unauthorized deploy being triggered by a deceived `deploy:stack`-permitted user relying on the forged CI status.

### Likelihood Explanation
Requires only that the attacker control (or previously onboard) one organization/app installation configured in the target Shipit instance's `github:` secrets — a normal, unprivileged position for any tenant/customer of a shared Shipit deployment — and craft a JSON body with mismatched `repository.owner.login` vs `repository.full_name`. No access to the victim org's secret, private key, or any Shipit credential is needed.

### Recommendation
After signature verification succeeds, assert that `repository.full_name`'s owner segment equals the `repository_owner` value used to select the verifying `webhook_secret` (or otherwise derive the target repository lookup from the same authenticated organization identity), rejecting the request (422) on mismatch — mirroring how the report's fix constrains `special_case` to only be assertable when `is_valid` holds.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, configured in this Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, raw_body)` — valid, because `verify_signature` looks up the secret for `attacker-org`.
4. `WebhooksController#create` passes signature check, then `Handler#repository_name` resolves `"victim-org/victim-repo"`, finding the real `Stack` tracked for the victim org, and `PushHandler#process` runs `sync_github` on it — or, for a `status` event, writes an attacker-controlled `Status` (e.g., `state: "success"`) on an arbitrary sha of the victim's tracked commit, despite the attacker never possessing `victim-org`'s webhook secret.

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
