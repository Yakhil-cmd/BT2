### Title
Webhook signature verified against `repository.owner.login` but the acted-upon `Repository` is resolved from the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
Shipit supports onboarding multiple independent GitHub organizations, each with its own `webhook_secret` (`config/secrets.development.shopify.yml`). The webhook signature is validated against the secret of the organization named in `repository.owner.login`, but every webhook `Handler` resolves the target `Stack`/`Repository` from the separate, unchecked `repository.full_name` field of the same JSON payload. Nothing enforces that these two fields refer to the same repository, so a party who legitimately controls one onboarded organization's webhook secret can forge a signed event that is authenticated as "their org" but is applied to a completely different, victim organization's stack.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from the payload and verifies the raw body against that organization's secret: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` selects that organization's `webhook_secret` for HMAC verification (`lib/shipit/github_app.rb#verify_webhook_signature`).

Once the signature check passes, the handler dispatch (`WebhooksController#create`) hands the *entire* raw payload to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. Every concrete `Handler` (push, status, check_suite, pull_request/*) resolves which `Stack` to act on via a second, independent field: [3](#0-2) 

`repository_name` is `payload.dig('repository', 'full_name')` — not `repository.owner.login`. GitHub's real webhook payloads keep these consistent, but the engine performs no cross-check that `full_name` starts with the verified `owner.login`. An attacker who legitimately configures/administers one org onboarded to a shared, multi-org Shipit deployment (and therefore knows that org's own `webhook_secret`, which they themselves set during GitHub App creation) can:
1. Sign an arbitrary JSON body with their own org's `webhook_secret`, satisfying `verify_webhook_signature`.
2. Set `repository.owner.login` to their own org (so the correct secret is selected and verification succeeds).
3. Set `repository.full_name` to `"victim-org/victim-repo"` — any repository/stack tracked elsewhere in the same Shipit instance.

`PushHandler#process` then calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` against the *victim* stack: [4](#0-3) 

The `status`, `check_suite`, and `pull_request/*` handlers use the identical `stacks`/`repository_name` lookup from the shared `Handler` base class, so the same forgery vector lets the attacker inject spoofed CI `Status` records and pull-request/merge-queue events onto the victim repository's commits and stacks.

This is the direct analog of the reported bug class: a privileged party (an org onboarded with its own credentials) is authenticated for one identity ("the organization that authenticated") but the code acts on a different, unchecked target ("the repository that is written") — exactly the binding equality called out in the rules ("an organization that authenticated versus the repository that is written").

### Impact Explanation
By forging the `repository.full_name` field while validly signing with their own organization's webhook secret, the attacker can inject fabricated `push`, `status`, and `check_suite` events for any stack hosted on the shared Shipit instance, regardless of which organization actually owns that repository. Spoofed `status` events create fabricated commit statuses that feed into CI-gated automation (required statuses, merge queue eligibility, continuous delivery triggers), and spoofed `push`/`check_suite` events force out-of-band `sync_github` resynchronization of a victim stack. Depending on the victim stack's continuous-delivery/merge configuration, this can unlock or trigger unauthorized merges/deploys on a repository the attacker has no legitimate access to — meeting the "unauthorized deploy, rollback or merge" Critical bar, or at minimum enabling cross-organization manipulation of stack/task state (High).

### Likelihood Explanation
Exploitation requires the attacker to be an administrator of at least one GitHub organization/App that is legitimately onboarded to a multi-organization Shipit instance (a supported and documented configuration, per `config/secrets.development.shopify.yml` and `docs/setup.md`), which they can do by owning their own org's `webhook_secret`. No access to the victim organization's secret, GitHub token, or Shipit session is needed — the payload's `repository.full_name` is fully attacker-controlled and never validated against the verified `owner.login`.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler#repository_name` (and/or centrally in `WebhooksController`), require that the repository/org used to resolve `stacks`/`Repository` matches the organization whose secret verified the request — e.g., assert `payload.dig('repository', 'full_name').to_s.start_with?("#{repository_owner}/")`, or better, pass the verified `repository_owner` into handler construction and have handlers scope repository lookups by that verified owner rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (attacker controls its GitHub App/webhook secret) and `victim-org` (hosts the target stack), as supported by the multi-org `secrets.yml` schema.
2. Attacker crafts a webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<arbitrary sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` and POSTs it with `X-Github-Event: push` to the shared Shipit webhook endpoint.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the signature verifies successfully.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, and calls `sync_github` on the victim's stack — an action the attacker was never authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
