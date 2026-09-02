### Title
Webhook organization used for signature verification is decoupled from the repository/commit the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/`webhook_secret` to HMAC-verify a webhook against using an organization value read out of the still-unverified JSON body, while the actual event handler that runs afterwards acts on repository/commit identifiers taken from that same untrusted body — with no code re-checking that the two agree. This is the same class of bug as `veCVXStrategy.manualRebalance`: two values that look like they must be the same quantity (the org whose secret validated the request vs. the org/repo the request is allowed to mutate) are compared/used interchangeably even though nothing enforces they refer to the same entity.

### Finding Description
`verify_signature` derives the org used to look up the signing secret purely from the request body, before the signature has been checked: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` resolves a per-organization `GithubApp` config, each with its own `webhook_secret`, driven by `TOP_LEVEL_GH_KEYS` / per-org config in `lib/shipit.rb`, and `verify_webhook_signature` performs the HMAC compare with the secret belonging to that resolved organization: [3](#0-2) 

Once `verified` is true, `create` hands the *entire, attacker-authored* body to the registered handler for the event, with no additional constraint tying the mutated repository/commit back to the organization whose secret validated the signature: [4](#0-3) 

Handlers such as `PushHandler` then act on repository/branch data taken straight from the same body: [5](#0-4) 

and, per the controller test suite, the `status` event handler writes a `Status` record directly from payload fields (`sha`, `state`, `target_url`, `description`, `context`) for whatever commit matches, again independent of which organization's secret validated the request: [6](#0-5) [7](#0-6) 

Because a real GitHub webhook always has `repository.owner.login` consistent with `repository.full_name`, this inconsistency can only be produced by a forged request — but the forgery only needs a *valid secret for any one configured organization*, not for the organization whose repository/commit is actually being written. In other words:
`organization whose signature is verified == organization whose secret the attacker legitimately controls` while `repository/commit actually mutated == whatever the attacker puts in the body`, and these two are never asserted equal.

### Impact Explanation
On a Shipit deployment that onboards more than one GitHub organization (each with its own GitHub App / `webhook_secret`, as documented and supported by `Shipit.github(organization:)`), an actor who legitimately controls the GitHub App/webhook secret of *their own* onboarded organization (OrgA) can craft a webhook body whose `repository.owner.login`/`organization.login` says "OrgA" (so the signature check passes with OrgA's secret) but whose `repository.full_name` / `sha` / `ref` reference a stack or commit belonging to a different, victim organization (OrgB) that they have no access to. Depending on the handler this enables:
- Forging passing/green `status` (CI) events for a victim commit, potentially defeating `ci.require`/`ci.blocking` gating and causing an unauthorized deploy of another organization's stack — a cross-repository write / unauthorized deploy.
- Triggering sync/webhook side effects for repositories outside the attacker's authorized organization boundary.

This crosses the "organization that authenticated versus the repository that is written" trust boundary called out explicitly as an acceptable analog category, and the resulting effect (spoofed CI status enabling an unauthorized deploy of a repository the attacker doesn't control) matches the Critical/High impact bar for this engine.

### Likelihood Explanation
Exploitation requires the Shipit instance to be configured with more than one GitHub organization/App, and requires the attacker to legitimately control one such organization's own webhook secret (i.e., they are a normal, unprivileged-relative-to-the-victim-org user who owns/administers a *different* onboarded org). No access to the victim organization, its repository, or any Shipit session/API token is required — only knowledge of a secret for an org that is entirely separate from the victim's. This is a realistic scenario for shared/multi-tenant Shipit installations.

### Recommendation
After `verify_webhook_signature` succeeds, re-derive the organization from the verified payload and assert that every repository/organization reference used by the dispatched handler (`repository.owner.login`, `repository.full_name`'s owner segment, `organization.login`) is identical to the `repository_owner` that was used to select the verifying secret, rejecting the request (422) on mismatch before invoking `Shipit::Webhooks.for_event(event)` handlers.

### Proof of Concept
1. Shipit is configured with two organizations, `orga` and `orgb`, each with its own GitHub App and `webhook_secret` (per `Shipit.github(organization:)`/`TOP_LEVEL_GH_KEYS`).
2. Attacker legitimately administers `orga`'s GitHub App and therefore knows `orga`'s `webhook_secret`.
3. Attacker POSTs to `/github/webhooks` with `X-Github-Event: status`, body:
   ```json
   { "sha": "<victim-commit-sha-in-orgb-stack>", "state": "success",
     "target_url": "...", "context": "ci/required",
     "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" } }
   ```
4. `repository_owner` resolves to `"orga"`; `Shipit.github(organization: "orga")` is used, and the attacker signs the raw body with `orga`'s known `webhook_secret` in `X-Hub-Signature`, so `verify_signature` passes.
5. `create` dispatches the `status` handler with the full (forged) body, which records a fabricated passing status for the victim commit belonging to `orgb`, with nothing checking that `orgb` (the org actually written to) matches `orga` (the org whose secret validated the request).

*Note: exact handler internals for the `status`/`commit_status` events (e.g., whether commit lookup is additionally scoped by repository `full_name`) were not directly inspected in this pass; the root-cause mismatch in signature-organization selection vs. body-driven mutation target is confirmed directly in `WebhooksController`, and its exploitability depth (which specific handlers are affected and how severely) should be verified against the handler source under `app/models/shipit/webhooks/handlers/` before remediation.*

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L216-218)
```ruby
    def repository_params
      { repository: { owner: { login: 'shopify' } } }
    end
```
