Based on my research, I found a concrete binding break in the webhook trust model.

### Title
Webhook signature verifies the sender's organization but handlers act on repository/commit data taken from elsewhere in the same unsigned-for-scope payload, allowing cross-repository status/push forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the incoming HMAC against using `repository_owner`, which is read from the JSON body itself (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Downstream handlers, however, resolve the *actual* target repository/stack/commit from different fields of that same body (`repository.full_name` in `Handler#repository_name`, or a bare, unscoped `sha` lookup in `StatusHandler`). Because the signature only proves "this body was signed by the secret of whatever org I claim in `repository.owner.login`," and the body is otherwise attacker-controlled JSON, nothing binds the organization that authenticated the request to the repository the handler subsequently mutates. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
This mirrors the reported bug class: a value is read from post-mutation/uncontrolled state and trusted as if it still reflected the pre-verified condition, letting a single legitimate credential (the attacker's own webhook secret for their own GitHub org) inflate their authority beyond that org's boundary — analogous to the balance being read after a partial checkpoint update instead of before.

Concretely:
- `verify_signature` picks the signing organization from the payload body (`repository_owner`), then verifies the raw body against that org's `webhook_secret` via `Shipit.github(organization: repository_owner).verify_webhook_signature`. [1](#0-0) 
- For most handlers, the actual mutation target is resolved via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a separate field from `repository.owner.login`. [3](#0-2) 
- For `StatusHandler`, there is no repository check at all: it looks up commits globally by SHA (`Commit.where(sha: params.sha)`) and writes a status onto whatever stack that commit belongs to, regardless of which org's secret was used to authenticate the request. [4](#0-3) 

Because an attacker who owns (or administers) their own organization configured in Shipit legitimately knows/controls that org's `webhook_secret` (they can set their own GitHub App/webhook to send whatever body they like, correctly signed), they can craft a JSON body where `repository.owner.login` / `organization.login` is their own org (so `verify_signature` succeeds against their own secret) while the "state"/effect-bearing fields (`repository.full_name` for push, or a known commit `sha` for status) reference a **victim** repository/stack tracked by Shipit under a different, unrelated GitHub App configuration. `verify_signature` never checks that `repository.full_name`'s owner matches `repository_owner`; it independently reads `repository.owner.login` (or falls back to `organization.login`) purely for secret selection, so the two fields can be made inconsistent within a single signed body.

The binding broken: `organization authenticated by verify_signature (repository_owner)` ≠ `repository/stack actually written by the handler (repository.full_name / commit.sha lookup)`.

### Impact Explanation
This is High: it grants unauthenticated-for-that-repo write access into Shipit's data model for a stack/repository that the attacker's own credentials do not cover. Via `StatusHandler`, an attacker can post fabricated commit statuses for a real commit SHA belonging to any tracked stack (SHAs are often publicly known via GitHub) without controlling that repository's GitHub App/webhook secret at all — `Commit.where(sha: params.sha)` performs no repository scoping. Fabricated "success" statuses feed into `Commit`/`Status` deployability computations used by continuous delivery and deploy-readiness checks in `app/models/shipit/stack.rb` and `app/models/shipit/commit.rb`, which can influence auto-deploy eligibility for a stack the attacker has no legitimate access to — an escalation into unauthorized state changes on another repository's deployment pipeline.

### Likelihood Explanation
High for any attacker who is a legitimate admin of at least one organization configured with a Shipit `webhook_secret` (a normal, unprivileged-relative-to-the-victim-repo setup): they can freely craft and correctly sign arbitrary JSON bodies for their own org, and the engine never cross-checks `repository.owner.login` against `repository.full_name` or against the commit's actual owning repository before dispatching to handlers.

### Recommendation
- In `WebhooksController`, after signature verification, re-derive the acting organization strictly from the same trusted field used for target resolution (e.g., parse `repository.full_name`'s owner segment) and require it to equal `repository_owner` used for signature verification, rejecting the request otherwise.
- In `StatusHandler` (and any handler that looks up records without going through `Handler#stacks`/`repository_name`), scope the `Commit`/`Status` lookup to commits belonging to a repository whose owner matches the authenticated `repository_owner`, instead of a global `sha` lookup.
- More generally, ensure every handler derives its target repository from the same field that `verify_signature` uses to select the signing secret, and reject payloads where these fields disagree.

### Proof of Concept
1. Attacker administers GitHub organization `attacker-org`, registered in Shipit with a known `webhook_secret`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-commit-sha-tracked-by-shipit>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature` as `sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)`.
4. POST to `/github/webhooks` (or engine-mounted webhooks path) with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` → `attacker-org`, fetches `attacker-org`'s app config, and successfully verifies the signature since the attacker signed with the correct secret for that org. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (owned by a completely different, unrelated repository/org), and writes a forged status onto it — with no verification that `attacker-org` has any relationship to that commit's repository. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
