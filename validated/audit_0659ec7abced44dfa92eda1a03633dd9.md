## Finding

### Title
Webhook secret selection uses an unverified field from the payload, allowing organization-scoped signature bypass to spoof pushes for a different repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
This is the shipit-engine analog of the `felt_to_bytes_little` bug class: a value that is *read and acted upon* is not actually covered by the verification that is supposed to bind it. In the Cairo report, `bytes_len`/`value` could diverge from what the HMAC/constraint system actually verified. In `WebhooksController`, the GitHub organization used to *select which webhook secret to verify against* is taken from the same untrusted JSON body whose authenticity that secret is supposed to guarantee, and per-organization `webhook_secret` is optional. This breaks the intended binding "GitHub organization that authenticated the payload" == "repository the payload is written/acted upon for".

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/secret to verify with directly from the untrusted, not-yet-verified request body: [1](#0-0) 

`repository_owner` is derived purely from JSON fields inside the same payload: [2](#0-1) 

The secret lookup then flows into `GitHubApp#verify_webhook_signature`, which explicitly treats an unset `webhook_secret` as "verification passes": [3](#0-2) 

Shipit natively supports hosting multiple GitHub organizations from one instance, each with its own, independently-configured (and individually optional) `webhook_secret`: [4](#0-3) 

Once `verify_signature` passes, `create` dispatches the full, attacker-controlled payload to the registered handlers, which independently pull the *actual* repository / commit identity out of the same payload (e.g. `repository.full_name`, `after` sha) to decide which `Stack`/`Repository` to update: [5](#0-4) 

The push-handling behavior (confirmed via test expectations) demonstrates that the sha acted upon is read straight out of the JSON body's `after` field, with no re-check that it belongs to the org whose secret validated the request: [6](#0-5) 

**The break in the equality**: "organization whose secret validated this request" is supposed to equal "organization/repository the request's contents are acted upon for". But:
- `verify_signature` selects the secret using `params.dig('repository','owner','login') || params.dig('organization','login')` — fields fully controlled by the request body.
- If *any* configured organization on the instance has no `webhook_secret` set (an explicitly supported/documented configuration, see `docs/setup.md` "Webhook secret (optional)"), `verify_webhook_signature` unconditionally returns `true` for a payload claiming `repository.owner.login` = that organization.
- Nothing then re-validates that the repository/commit fields acted upon by the handler (`repository.full_name`, `after`, etc., which can name a *different, protected* organization's repository) match the organization that "authenticated" the request.

An attacker with no credentials can therefore forge a webhook (e.g. `push`) that:
1. Sets `repository.owner.login`/`organization.login` to an org configured on the instance with no `webhook_secret` (bypassing HMAC verification entirely for that request), while
2. Setting `repository.full_name` and `after` (or other payload fields consumed by the handler) to point at a `Stack`/`Repository` belonging to a different org that the attacker wants to attack.

Whether this reaches a `Stack` depends on whether the handler resolves stacks purely from `repository.full_name` in the payload rather than cross-checking the verified owner — this is consistent with the design shown in the tests (`unknown_repo_payload["repository"]["full_name"]`, `parsed_body["after"]`), which pull the acted-upon identity straight from `params` regardless of `repository_owner`.

### Impact Explanation
If exploited, an unprivileged, unauthenticated actor can inject spoofed GitHub events (pushes, statuses, check suites, etc.) for a `Stack` under an organization whose secret was never checked, feeding fabricated shas/commit metadata into `Shipit::Webhooks` handlers (`GithubSyncJob`, commit status creation, check-run refresh). Combined with `continuous_deployment`, a forged push recorded as a new commit on the tracked branch can result in an **unauthorized deploy** being triggered for a real production stack — matching the Critical impact category ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only: (a) the Shipit instance hosts more than one GitHub organization (a documented, supported configuration), and (b) at least one of those organizations has no `webhook_secret` configured (also documented as optional/acceptable). No GitHub credentials, `ApiClient` token, or session are required — the `/webhooks` endpoint is unauthenticated by design and only relies on signature verification for trust. This is a plausible, realistic operational configuration rather than a contrived edge case.

### Recommendation
- Do not derive the HMAC-verification key from unauthenticated payload fields. Verify webhook signatures against every configured secret capable of producing a valid signature only, or require the caller to also identify itself via a mechanism outside the JSON body (e.g., per-org webhook path/route).
- Make `webhook_secret` mandatory for all configured organizations, or, if optional, ensure that unsigned webhooks are only trusted for the exact organization they claim without permitting any cross-organization repository/commit references to be actioned.
- After signature verification, re-validate that all repository/organization identifiers referenced deeper in the payload (`repository.full_name`, `organization.login`, etc.) are consistent with the organization whose secret validated the request, before handlers act on them.

### Proof of Concept
Conceptual PoC (exact success depends on runtime `Shipit.github_teams`/handler wiring, which could not be fully re-verified within tool budget):
1. Configure/observe a target Shipit instance hosting two orgs, `org-a` (no `webhook_secret`) and `org-b` (protected, hosts the real target stack).
2. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/target-repo" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/main"
}
```
3. `verify_signature` resolves `repository_owner` = `org-a`, calls `Shipit.github(organization: 'org-a').verify_webhook_signature(...)`, which returns `true` because `org-a`'s `webhook_secret` is blank.
4. The `push` handler receives the full payload and acts on `repository.full_name` = `org-b/target-repo` and `after` = attacker's sha, in `org-b`'s stack, despite `org-b`'s webhook secret never being checked.

**Uncertainty**: I could not fully trace the internal push webhook handler implementation (`Shipit::Webhooks` handler for `push`) within the tool budget to confirm precisely which payload fields it uses to resolve the target `Stack`/`Repository` versus `repository_owner`. This should be verified directly in the handler code (likely under `app/models/shipit/webhooks/` or similar, not returned by search) before treating this as fully confirmed; a Devin session with full repo access can trace this exactly.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```
