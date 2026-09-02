### Title
Cross-organization webhook injects fabricated CI status onto another org's commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` derives the signing organization solely from the attacker-controlled JSON body (`params.dig('repository','owner','login')`), so an attacker can sign a `status` webhook with their own org's `webhook_secret` while the body's `sha` names a commit belonging to a different org's stack. `StatusHandler#process` then resolves the commit with an unscoped `Commit.where(sha: params.sha)` query and calls `create_status_from_github!` on every match, with no check that the verifying org actually owns that commit's repository.

### Finding Description
The broken binding: `repository_owner_used_for_signature_verification == repository_owner_of_the_matched_commit` should hold, but it does not.

- `app/controllers/shipit/webhooks_controller.rb:59-62`: `repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) straight from the untrusted, attacker-supplied JSON body. [1](#0-0) 
- `app/controllers/shipit/webhooks_controller.rb:24-30`: `verify_signature` looks up `Shipit.github(organization: repository_owner)` using that attacker-supplied value and verifies the HMAC signature against *that org's* `webhook_secret`. [2](#0-1) 
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`: `StatusHandler#process` matches commits purely by `sha`, globally, with no join/filter on `Repository`/`Stack` ownership, then calls `commit.create_status_from_github!(params)`. [3](#0-2) 

Root cause: the `repository` field used for signature scoping and the `sha` field used for record lookup are two independent, attacker-controlled fields in the same JSON body, and nothing ties them together. An attacker who owns any GitHub org registered in Shipit (with its own legitimate `webhook_secret`) can:
1. Compute `X-Hub-Signature` over a crafted JSON body using their own org's `webhook_secret`.
2. Set `repository.owner.login` (or `organization.login`) in the body to their own org, so `verify_signature` succeeds.
3. Set `sha` in the body to a known commit sha belonging to a victim stack/org.
4. POST to `/webhooks` with header `X-Github-Event: status`.

`verify_signature` passes (their own secret, their own claimed org), `drop_unhandled_event` passes (status is handled), and `StatusHandler#process` finds the victim's `Commit` by sha alone and writes fabricated `state`/`description`/`target_url` onto it via `create_status_from_github!`.

None of the existing guards prevent this: `verify_signature` only proves the request was signed by *some* registered org's secret, not that it was signed by the org that owns the commit referenced in the payload; `drop_unhandled_event` only checks the event type; `ExplicitParameters` (the `params do ... end` block) only validates presence/types of `sha`/`state`/etc., not repository ownership; and there is no `Stack`/`Repository` scoping anywhere in `StatusHandler`.

### Impact Explanation
A successfully forged status can flip a required/deploy-gating CI check to `success` on a victim's commit, which can influence downstream merge/deploy gating logic that consults commit statuses, i.e., a payload authenticated for one repository mutates another repository's commit/stack state. This matches the "Critical" category: a payload for one repository mutating another's commit/stack, and potentially enabling an unauthorized deploy. Blast radius: any org with a registered `webhook_secret` in the multi-tenant Shipit instance can target any other tenant's commits, as long as the sha is known/guessable (shas are generally public information visible via GitHub).

### Likelihood Explanation
Preconditions: attacker must control (own) at least one org that is registered in Shipit's GitHub app configuration with a valid `webhook_secret` (a normal, low-cost setup for any legitimate but unprivileged tenant in a multi-org Shipit deployment), and must know a target commit sha for a victim stack (commit shas are public GitHub data, not secrets). Given these, the attack is a single unauthenticated HTTP POST to `/webhooks`, fully repeatable and scriptable, requiring no session, API token, or GitHub write access to the victim's repository.

### Recommendation
Scope the commit lookup in `StatusHandler` (and any other handler using bare `sha`/global lookups) by the verified `repository_owner`/`repository.full_name` from the signature-verification step, e.g. join through `Commit -> Stack -> Repository` and filter `repository.owner == verified_repository_owner` (and ideally repository name too) before calling `create_status_from_github!`. More generally, `WebhooksController` should pass the verified repository identity down to handlers instead of letting each handler re-trust the raw body's fields independently of what was used for signature verification.

### Proof of Concept
Minitest plan (no live GitHub calls, using existing test fixtures/secrets from `test/dummy/config/secrets*.yml`):
1. Create `attacker_org` and `victim_org` fixtures, each with distinct `webhook_secret`s in Shipit's github config (mirroring existing test setup in `test/controllers/webhooks_controller_test.rb`).
2. Create a `Repository`/`Stack`/`Commit` owned by `victim_org` with a known `sha` and initial status `pending`.
3. Build a `status` webhook JSON body with `sha` = victim commit's sha, `state` = `success`, and `repository.owner.login` = `attacker_org`.
4. Compute `X-Hub-Signature` using `attacker_org`'s `webhook_secret` over that body.
5. POST to `/webhooks` with `X-Github-Event: status` and the crafted signature.
6. Assert the response is `200 OK` (signature accepted).
7. Assert on the binding: before, `commit.status_for('context').state != 'success'`; after the request, `commit.reload.status_for('context').state == 'success'` — proving that a payload signed by `attacker_org`'s secret mutated a commit belonging to `victim_org`'s stack, with `commit.create_status_from_github!` invoked despite no ownership relationship between `attacker_org` and the victim's repository.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
