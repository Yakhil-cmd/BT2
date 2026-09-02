### Title
Webhook Signature Verification Is Scoped to a Self-Declared Organization While Status Writes Are Globally Unscoped by Repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook against using an organization name taken directly from the *unverified* request body (`repository.owner.login`/`organization.login`). Once the HMAC check for that self-declared organization passes, `Webhooks::Handlers::StatusHandler` writes a commit status by looking up `Commit.where(sha: params.sha)` **globally across the entire Shipit installation**, with no check that the matched commit even belongs to a stack owned by the organization whose signature was verified. This is the same class of bug as CVE-2026-34377: a narrow identity/signature check (`txid` in Zebra, "organization" here) is treated as proof of full authorization over a broader payload (full transaction authorization data in Zebra, arbitrary cross-repo commit state here).

### Finding Description
`Shipit` supports hosting multiple GitHub organizations in one instance, each with its own, independently-configured `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`, which explicitly states the webhook secret is *optional*).

`WebhooksController#verify_signature` picks the GitHub App/secret to validate against using data taken from the raw, not-yet-verified payload: [1](#0-0) [2](#0-1) 

The signature verification itself, in `GitHubApp#verify_webhook_signature`, unconditionally returns `true` if that organization's `webhook_secret` is blank: [3](#0-2) 

Once the request passes this org-scoped check, `WebhooksController#create` dispatches the *entire* raw JSON body to the matching event handler: [4](#0-3) 

`StatusHandler#process`, however, does not use the repository-scoped `stacks` helper that other handlers use (e.g. `PushHandler`, `CheckSuiteHandler` via `Handler#stacks`/`#repository_name`). Instead it resolves target commits purely by SHA, with no repository binding at all: [5](#0-4) 

The equality that the CVE analog breaks is:

`organization whose webhook_secret verified the request` **≠** `repository/stack whose commit status is actually written`

Before the attacker's request: a commit status for stack/repo `victim-org/victim-repo`, commit `sha`, can only be updated by a webhook signed with `victim-org`'s secret (as intended by the per-organization GitHub App model).

After the attacker's request: an attacker who controls (or who targets) any organization configured in `Shipit.secrets.github` — particularly one with no `webhook_secret` set, which the documentation calls "optional" — can submit a `status` event whose `repository.owner.login` matches that org (satisfying `verify_signature`), while the `sha` field matches a commit belonging to a completely different stack/repository elsewhere in the same Shipit instance. `StatusHandler` will happily create/overwrite a `Status` on that unrelated commit.

### Impact Explanation
Commit statuses recorded via `Commit#create_status_from_github!` are the mechanism Shipit uses to represent CI/CD state for gating things like mergeability and deploy readiness (`Status`-related logic referenced throughout `app/models/shipit/stack.rb` and `app/models/shipit/commit.rb`). Forging a `success` status on an arbitrary victim commit — reachable by any attacker who can get one org's webhook accepted (including a no-secret org) — lets an unprivileged external actor manipulate deploy/merge-readiness signals for repositories/stacks they have no legitimate relationship to, an "unauthorized deploy/merge" class impact per the scan's accepted-impact list. This crosses a genuine authorization boundary: the webhook subsystem is designed so that an organization's GitHub App/secret should only be able to speak for that organization's repositories, but `StatusHandler` never enforces that binding.

### Likelihood Explanation
Exploitability depends entirely on engine code, not on host misconfiguration in the sense the rules exclude: multi-org GitHub App support and optional `webhook_secret` are first-class, documented features of the engine (`docs/setup.md`, `secrets_double_github_app.yml`). Any deployment that (a) hosts more than one organization, or (b) leaves a `webhook_secret` unset for any one of its configured organizations (both explicitly supported/optional per the docs) gives an unauthenticated attacker a working signature bypass for that organization's identity, which `StatusHandler` then lets leak into every other organization's commits.

### Recommendation
Scope `StatusHandler` (and any other handler that does not already use `Handler#stacks`) to the repository declared in the verified payload, and cross-check that repository's owning organization against the organization whose secret validated the request, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
More generally, `WebhooksController` should thread through the organization that was actually used to verify the signature and every handler should assert that the repository/organization referenced in the payload for state-mutating operations matches it, rather than re-trusting the raw payload's `repository`/`organization` fields a second time without re-validation.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` (no `webhook_secret` set, per the documented "optional" setting) and `VictimOrg` (has a Stack tracking `VictimOrg/victim-repo`, with a commit `deadbeef...` currently pending).
2. As an unauthenticated attacker (no Shipit session, no API token, no knowledge of any secret), POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": {"owner": {"login": "OrgOne"}, "full_name": "OrgOne/some-repo"},
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example/fake",
  "created_at": "2026-09-01T00:00:00Z"
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgOne")`; because `OrgOne.webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `StatusHandler#process` executes `Commit.where(sha: "deadbeef...")`, matches the commit under `VictimOrg/victim-repo`, and writes a forged `success` status for it — despite the request never being authenticated as `VictimOrg`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
