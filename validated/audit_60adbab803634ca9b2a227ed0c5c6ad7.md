This finding confirms an exploitable analog. The webhook signature verification binds only to `repository.owner.login` (or `organization.login`), while the actual repository the event acts on is taken from a completely different, unverified field: `repository.full_name`.

### Title
Webhook signature scoped to `repository.owner.login` while event dispatch trusts unverified `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
In multi-org Shipit deployments (`Shipit.github(organization:)` keyed per GitHub org, each with its own `webhook_secret`), `WebhooksController#verify_signature` selects which org's secret to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')`. Once the signature is accepted, all downstream `Handler` subclasses (e.g. `PushHandler`) instead resolve the target `Repository`/`Stack` using a **different** JSON field: `payload.dig('repository', 'full_name')`. These two fields are independent, attacker-controlled strings within the same JSON body and are never cross-checked against each other.

### Finding Description
`verify_signature` in [1](#0-0)  computes:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` comes from [2](#0-1) . This only proves the payload was signed with the secret belonging to whatever organization is named in `repository.owner.login`/`organization.login`.

However, event processing in `Handler#stacks` uses a separate field to look up the affected repository: [3](#0-2) , and `Repository.from_github_repo_name` in [4](#0-3)  parses `owner/name` straight out of that string.

Because the entire `X-Hub-Signature` HMAC is computed over the full raw body, an attacker who legitimately administers **any one** configured GitHub App/organization (and therefore knows that organization's `webhook_secret` — a normal, non-privileged-to-Shipit capability for someone who owns/administers their own org's GitHub App settings) can craft an arbitrary JSON body where `repository.owner.login` (and/or `organization.login`) is set to their own organization (so signature verification passes with the secret they know), while `repository.full_name` is set to `"victim-org/victim-repo"`. The signature check never inspects `full_name`, so the forged event is accepted and dispatched to handlers that act on the victim repository/stack.

This is the same class of bug as the reported `createArt` issue: the cryptographic proof (the artist's/organization's signature) is verified over one identity/field, while a *different*, unchecked field is what execution actually acts upon — breaking the intended binding "the org that authenticated == the repository that is written."

### Impact Explanation
An attacker who controls a legitimately-configured GitHub organization/app in a multi-org Shipit install can forge webhook events (`push`, `check_suite`, `status`, `pull_request`, `membership`, etc.) that Shipit will process as if they originated from a **different** organization's repository. Concretely:
- Forged `push`/`status`/`check_suite` events can trigger `Stack#sync_github`, `RefreshCheckRunsJob`, or commit/status updates against a victim stack the attacker does not own, corrupting deploy state, injecting fabricated CI statuses, or triggering syncs of arbitrary commit SHAs into a stack that a legitimate deploy/merge decision may depend on.
- `membership`-type handlers can create/modify `Team`/`Membership`/`User` records tied to victim teams, potentially escalating group membership used by `Shipit.github_teams` authorization checks (`app/controllers/concerns/shipit/authentication.rb`), which is explicitly listed as a High-impact escalation target.

This does not itself leak `GITHUB_TOKEN`, but it does let an unprivileged-to-Shipit but org-owning attacker cross the "organization that authenticated versus the repository that is written" boundary, matching the High-severity bucket (escalation into `Shipit.github_teams` authorization / unauthenticated manipulation of stack state).

### Likelihood Explanation
This requires the deployment to use the documented multi-org `github:` config (`docs/setup.md`, "Using Multiple GitHub Applications") with more than one organization configured, and the attacker must control/administer at least one of those configured GitHub Apps (a realistic scenario for shared Shipit instances serving multiple orgs/teams, which is exactly the use case this feature exists for). No Shipit session, API token, or private key is needed — only knowledge of one's own org's `webhook_secret`, which is by design known to that org's admins.

### Recommendation
In `WebhooksController`, after determining `repository_owner` and verifying the signature, re-validate that every repository-identifying field actually used by handlers (`repository.full_name`, `organization.login`) is consistent with the `repository_owner`/org used to select the signing secret, rejecting the request (422) on mismatch. Alternatively, have `Handler#repository_name` derive the owner strictly from the same field validated during signature verification rather than trusting `repository.full_name` independently.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OrgA` (attacker-administered, secret known: `secretA`) and `OrgB` (victim, unknown secret):
```
payload = {
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },      # used only for signature org selection
    "full_name": "OrgB/victim-repo"    # used by PushHandler to find the Stack
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', secretA, payload)

POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<signature>
Body: payload
```
`verify_signature` calls `Shipit.github(organization: "OrgA").verify_webhook_signature(signature, payload)`, which succeeds since the attacker knows `secretA` and the HMAC covers the whole raw body they control. `PushHandler#stacks` then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — an event the attacker was never authorized to send for `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
