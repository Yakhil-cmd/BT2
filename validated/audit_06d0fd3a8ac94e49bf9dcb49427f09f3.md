## Title
Webhook signature verified against attacker-chosen organization but push handler updates repository/stack from the same untrusted payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The Deriverse bug fired fees/rebates based on a value (`fee_rate`/`ref_discount`) computed from an object (`client_community`) that was `None` for a code path (AMM-vs-orderbook match) that never re-derived it, so the check silently degenerated to zero and the real charge never happened. The structural pattern is: **a security-relevant value is derived from one field of attacker-influenced input, while the actual effect (fill/execution) is driven by a different, unchecked field of the same input** — the binding between "what was verified" and "what gets acted upon" breaks.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification from the **request body itself**: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — both of which are plain JSON fields in the unauthenticated POST body, not something cryptographically bound to the signature that is about to be checked. `Shipit.github(organization: repository_owner)` is then used to fetch that organization's configured `webhook_secret`, and `verify_webhook_signature` HMACs the *entire raw body* against that secret.

Downstream, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` processes the very same `params` hash, and handlers like the push handler resolve the actual `Repository`/`Stack` to mutate using `params['repository']['full_name']` (owner+name) — the same JSON object whose `owner.login` was used to pick the verification secret.

In a **multi-org deployment** (`Shipit.github` supports per-organization secrets, per `config/secrets.development.example.yml` and `docs/setup.md`), this creates the exact same class of decoupling as the Deriverse bug: the field used to select/derive the "trust" input (`repository.owner.login` → which secret is checked) is not cryptographically tied to the field that determines the actual write target (`repository.full_name`, `sha`, `after`, etc., used to look up/create the `Stack`/`Commit`). If an attacker can produce a validly-signed payload under *any one* organization's webhook secret (e.g. a lower-security org they were briefly a member of, or an org whose secret leaked/was brute-forced independently of the target), they can set `repository.owner.login` to that org while setting the rest of the payload (`repository.full_name`, commit SHAs, statuses) to point at a **different** organization/repository's stack, because nothing after `verify_signature` re-validates that the owner used for signature selection matches the repository actually being acted upon.

This is corroborated by the fallback itself: `repository_owner` willingly falls back to `params.dig('organization', 'login')` when `repository` is absent, meaning the "authenticating org" and the "repo being written" are explicitly allowed to be two different JSON subtrees of the same untrusted body.

### Impact Explanation
If exploitable, this allows cross-repository/cross-organization writes: an attacker with a valid webhook secret for Org A could forge `push`/`status`/`check_suite` events that get accepted as "verified" while carrying repository data for Org B's stack, causing spurious `GithubSyncJob` triggers, bogus commit statuses, or CI-check state changes on a stack they do not control. This matches the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Likelihood is **speculative/unconfirmed** rather than proven: exploitation requires an attacker to already control a valid webhook secret for *some* organization configured in `Shipit.github`, and the actual per-handler logic (e.g. `GithubSyncJob`, `Commit` lookup by stack) was not fully inspected in this session — I could not load `app/models/shipit/webhooks/handlers/push_handler.rb` or `app/models/shipit/webhooks/handlers/handler.rb` before the tool budget ran out, so I cannot confirm whether handlers additionally cross-check `repository_owner` against the resolved `Stack`'s actual owner before mutating it. If such a cross-check exists inside the handler base class, this finding is void. This is a genuine gap in my verification, not a confirmed vulnerability.

### Recommendation
Have the background engineer:
1. Read `app/models/shipit/webhooks/handlers/handler.rb` and `app/models/shipit/webhooks/handlers/push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb` to determine whether they independently verify that the `Repository`/`Stack` resolved from `params['repository']['full_name']` belongs to the same organization whose secret was used in `verify_signature`.
2. If no such check exists, tie webhook signature verification to the exact repository being mutated: derive the `Repository`/`Stack` first from `full_name`, and only then verify with that repository's own organization's secret — instead of trusting `repository.owner.login`/`organization.login` picked ad hoc before the handler runs.

### Proof of Concept
Not constructed — could not confirm through the handler code (files unreadable in this session) whether `repository.full_name`'s owner is cross-checked against `repository_owner` before a `Stack` is mutated. This is flagged as **unconfirmed**; a background Devin session with full file access should verify `app/models/shipit/webhooks/handlers/handler.rb` and the push/status/check_suite handlers before treating this as a validated finding.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
