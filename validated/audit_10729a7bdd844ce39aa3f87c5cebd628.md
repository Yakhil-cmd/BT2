### Title
Webhook events are trusted and applied to arbitrary repositories/stacks without verifying they belong to the GitHub organization whose secret signed the request - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a request against using an attacker-controlled field of the unverified JSON body (`repository.owner.login` / `organization.login`), then, once *any* valid HMAC is found, hands the *entire* raw body to event handlers that resolve the target repository/stack/commit from **other** attacker-controlled fields in the same body (`repository.full_name`, `sha`) with no check that those fields belong to the organization that produced the valid signature.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to verify against by reading the untrusted payload itself: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` only proves that the raw body was HMAC-signed with *some* configured organization's `webhook_secret` — it says nothing about which repository the body actually describes: [3](#0-2) 

Once the (correctly, but org-A-selected) signature check passes, the handlers dispatched from `WebhooksController#create` derive the actual repository/commit to mutate from *other* fields of that same body, independent of `repository.owner.login`:

- Generic handler base class resolves the target `Repository`/`Stack` purely from `repository.full_name` in the payload: [4](#0-3) 

- `PushHandler` applies this to any stack matching that repository/branch, triggering a GitHub sync: [5](#0-4) 

- `StatusHandler` is even less scoped: it matches purely by commit SHA across the **entire** instance, with no repository check at all: [6](#0-5) 

The equality that should hold but doesn't: `organization whose webhook_secret authenticated the request == organization that owns repository.full_name / the commit acted on`. Because `verify_signature` derives the lookup key from the same untrusted body it is about to validate, and downstream handlers never re-check the org/repository ownership after verification, any principal who legitimately controls a webhook secret for **one** organization/App installed on this Shipit instance (e.g. an org admin, or anyone who obtains that org's `webhook_secret` through legitimate means — a routine, low-privilege operation compared to compromising the Shipit deploy host itself) can forge a validly-signed webhook body whose `repository.owner.login` matches their own org (so signature verification passes) while `repository.full_name`/`sha` reference a completely different organization's stack tracked by the same Shipit instance.

### Impact Explanation
This breaks a repository/organization trust boundary: an attacker with a secret scoped to organization A can inject or manipulate GitHub events (pushes, commit statuses, pull-request/review-stack lifecycle events) for organization B's stacks, which A has no legitimate access to. Most notably, `StatusHandler` lets the attacker call `Commit#create_status_from_github!` for any commit SHA in the whole Shipit database, forging a fabricated "success" CI status on a victim commit. Since Shipit's deploy UI/automation gates deployability on commit status ("green build"), this can trick a legitimate, authorized Shipit user (or continuous-deployment schedule) into shipping a commit that never actually passed CI/checks — an unauthorized deploy condition. `PushHandler` similarly lets the attacker trigger `GithubSyncJob`/`sync_github` against arbitrary stacks, and the pull-request handlers let the attacker archive/unarchive/provision review stacks belonging to another organization's repository. This satisfies the "unauthorized deploy" / cross-repository-writes impact bar.

### Likelihood Explanation
Requires only that the attacker control a `webhook_secret` for any organization/App configured on the Shipit instance (the multi-org config format used in this engine, `test/dummy/config/secrets_double_github_app.yml`, shows this is a supported deployment pattern with distinct per-org secrets). No Shipit session, API token, or GitHub write access to the victim repository is needed — only knowledge of one org's webhook secret and the target commit SHA / repository full name (both public, observable GitHub data). This is unprivileged relative to the victim organization.

### Recommendation
After `verify_signature` succeeds, bind the verified organization to the rest of request processing: re-derive/require that `repository.full_name`'s owner (and any commit's owning repository in `StatusHandler`) matches the organization key used to select the webhook secret, and reject the event (422) if they diverge. `StatusHandler` in particular should scope its `Commit` lookup by repository, not global SHA.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as shown in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker legitimately obtains/knows `OrgA`'s `webhook_secret` (e.g. is an admin of `OrgA`'s GitHub App).
3. Attacker crafts a `status` event JSON body:
   ```json
   {
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/decoy"},
     "sha": "<victim commit sha belonging to OrgB/real-project>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and the signature is valid for `OrgA`'s secret, so the request passes.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — which finds the victim's commit belonging to `OrgB/real-project` regardless of the `repository` field used for verification — and calls `create_status_from_github!`, injecting a forged "success" status onto a commit the attacker has no access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
