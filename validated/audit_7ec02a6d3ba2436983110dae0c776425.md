### Title
Cross-Repository Commit Status Forgery via Webhook Signature/Payload Binding Mismatch - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The reported bug class is a mismatch between a value used to establish a security limit and the value that actually governs runtime behavior (`MAXIMUM_GAS_LIMIT` enforced vs. `gasleft()` actually observed). The equivalent binding in Shipit is: **the organization whose webhook secret authenticates the request signature** must equal **the repository/stack whose state the webhook handler is allowed to mutate**. `WebhooksController#verify_signature` binds the HMAC check to `repository_owner`, an attacker-controlled JSON field, while `StatusHandler#process` mutates commit state keyed purely on `sha`, with no re-validation that the commit belongs to the organization that was actually authenticated.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the `X-Hub-Signature` against using a value taken directly from the untrusted JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')`, fully controlled by whoever sends the POST body. `verify_webhook_signature` only checks that the HMAC matches `Shipit.github(organization: repository_owner)`'s secret: [3](#0-2) 

Once the request is authenticated as belonging to *some* organization onboarded on the Shipit instance, the dispatched handler processes the *rest* of the same payload — fields that were never independently bound to that organization. `StatusHandler#process` is the clearest break: it looks up commits **only by `sha`**, with no repository/stack scoping at all: [4](#0-3) 

Contrast this with the base `Handler` class, which does scope by repository via `repository_name = payload.dig('repository', 'full_name')` for other handlers such as `PushHandler`: [5](#0-4) [6](#0-5) 

`StatusHandler` does not use `stacks`/`repository_name` at all — it is not scoped to the organization/repository that the signature check authenticated. Since `sha` values (git commit hashes) are public knowledge for any public GitHub repository, an attacker who legitimately controls one onboarded organization (and therefore knows/derives a valid signature for their own `webhook_secret`) can submit a `status` event whose `repository.owner.login` is their own org (so the signature check passes) but whose `sha` is a commit belonging to a **different** stack/repository on the same Shipit instance. The equality the design assumes — `organization_authenticated == repository_written` — is broken: the org that authenticates the request and the commit/stack that gets mutated are unrelated.

### Impact Explanation
`Commit#create_status_from_github!` records CI/CD statuses that Shipit's merge queue and deploy pipeline check against `shipit.yml`'s `ci.require`/`merge.require` configuration. An attacker who is a legitimate but unprivileged organization/repository owner on a shared multi-tenant Shipit deployment can forge a "success" status for a required CI context on a **victim's** commit in a completely different repository, without ever needing that victim organization's webhook secret, an `ApiClient` token, or a Shipit user session. This can unblock the victim's merge queue or deploy gating (unauthorized merge/deploy), satisfying the Critical/High impact bar defined for this exercise (unauthorized deploy/merge via a broken authentication-to-target binding).

### Likelihood Explanation
Exploitability requires: (1) the attacker legitimately controls at least one organization/repo onboarded to the same Shipit instance (a normal, unprivileged tenant — not requiring any Shipit-internal secret), and (2) knowledge of the victim's target commit SHA, which is public for any commit pushed to GitHub. Both conditions are realistic in any multi-tenant Shipit deployment serving more than one team/organization, making this a practically reachable, low-effort attack once tenancy is shared.

### Recommendation
Bind the authenticated organization to the object being mutated for every handler, not just some. `StatusHandler` (and any other handler that does not use the `Handler#stacks`/`repository_name` scoping) should verify that the commit(s) matched by `sha` actually belong to a stack under the `Repository` derived from the same `repository.full_name`/`repository.owner.login` that `WebhooksController#verify_signature` used to select the webhook secret, rejecting the event otherwise.

### Proof of Concept
1. Attacker legitimately owns organization `attacker-org`, onboarded to the shared Shipit instance with its own configured `webhook_secret`.
2. Attacker learns (via public GitHub) the SHA of a commit belonging to `victim-org/victim-repo`, a repository tracked by a different stack on the same Shipit instance, whose merge/deploy pipeline requires a `ci` context (e.g. `codeclimate`) to report `success`.
3. Attacker crafts a `status` webhook payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "codeclimate",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
   }
   ```
4. Attacker signs the raw body with `attacker-org`'s own `webhook_secret` and sends it to `POST /webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s secret, and the signature check passes.
6. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the victim's commit (unscoped by repository), and calls `commit.create_status_from_github!(params)`, recording a forged `success` status for `codeclimate` context on the victim's commit — potentially satisfying `merge.require`/`ci.require` and permitting an unauthorized merge or deploy on `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
