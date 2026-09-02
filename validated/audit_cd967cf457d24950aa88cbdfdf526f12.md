### Title
Webhook signature is validated against the payload's `repository.owner.login`, but event handlers dispatch on the payload's `repository.full_name` with no cross-check, allowing a legitimate GitHub App installation to forge events for any other org's tracked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the `X-Hub-Signature` against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). Separately, every event `Handler` locates the target `Stack`/`Repository` using a *different* field of the very same payload: `payload.dig('repository', 'full_name')`. Nothing in the request path checks that the owner segment of `full_name` matches the `repository.owner.login`/`organization.login` used to pick the signing secret. [1](#0-0) [2](#0-1) 

### Finding Description
This is the same class of bug as the Augur report: a field that is *acted upon* is not the field that is *covered by the trust check*. In Augur, `totalAffiliateFeesAttoCash` (the aggregate invariant) was never updated even though `affiliateFeesAttoCash[affiliate]` (the per-entry value that was acted upon) was zeroed — the two values that were supposed to stay in lockstep diverged.

Here, the invariant that Shipit relies on for multi-tenant safety is:
```
organization used to select webhook_secret (repository.owner.login) == owner segment of repository.full_name used to locate the Stack
```
Both fields live inside the same signed JSON body, so the HMAC does cover both bytes — but the code never *asserts* the equality above. GitHub webhook payloads are attacker/customer-supplied for GitHub Apps installed by a Shipit operator on multiple organizations (a very common Shipit deployment). A push/status/check_suite payload's `repository` object always contains both `owner.login` and `full_name` as independently settable JSON keys from GitHub's perspective, but an operator who controls (or has compromised, e.g. via a misconfigured redelivery/replay tool, or a GitHub App that they administer for org "attacker-org") the ability to send an arbitrary payload signed with `attacker-org`'s `webhook_secret` can set:
```json
"repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
```
`verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and verifies successfully because the payload really was HMAC-signed with `attacker-org`'s own secret — this is a value the attacker legitimately possesses via their own installation on their own org. `WebhooksController#create` then dispatches to the handler with the full payload, and `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) resolves `Repository.from_github_repo_name('victim-org/victim-repo')`, matching whatever repository/stack Shipit has registered for `victim-org`, regardless of who authenticated.

`PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) then calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack, `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) schedules check-run refreshes against victim commits, and `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) writes a forged commit status onto whatever commit SHA the attacker names (status lookups are global, by `Commit.where(sha:)`, with no organization scoping at all).

### Impact Explanation
An attacker who legitimately controls a GitHub App installation/secret for any one organization tracked by a shared Shipit instance can forge webhook events attributed to a different, victim organization's repositories that are also tracked by that same Shipit instance. This crosses the "an organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Concretely reachable, unauthenticated-relative-to-the-victim consequences include:
- Forged `status` events writing arbitrary commit statuses onto victim commits (`StatusHandler`), which can flip Shipit's "green" gating used to permit deploys/merges.
- Forged `push`/`check_suite` events triggering `sync_github`/check-run refresh against victim stacks, corrupting Shipit's view of the victim's deploy state.

This does not by itself yield RCE or `GITHUB_TOKEN` exfiltration, so it falls short of "Critical", but it does escalate write access to another organization's stack state through a webhook channel that was supposed to be scoped per-organization, which aligns with the "High" bucket (state manipulation across a trust boundary the app is documented to enforce per-org).

### Likelihood Explanation
Requires the attacker to already operate/administer a legitimate GitHub App installation on at least one organization tracked by the same Shipit instance (i.e., a multi-tenant deployment), and to be able to craft/replay a raw signed payload (not just use GitHub's UI) — GitHub itself would not normally emit a payload whose `owner.login` and `full_name` owner disagree, so this requires either a compromised/malicious tenant crafting the HTTP request directly, or replay/tooling that lets a customer control the raw POST body sent to `/webhooks`. This is a real but narrower likelihood than a fully unauthenticated attack, since it presupposes a valid webhook secret for one tenant in a shared instance.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, after signature verification, assert that the resolved `repository_owner` used for the signing-secret lookup equals the owner segment of `payload.dig('repository', 'full_name')` (and of `organization.login` for org-level events) before dispatching to any handler; reject the event (422) on mismatch.

### Proof of Concept
Not executed against a live instance (no session, secrets, or filesystem access available in this analysis). Conceptual PoC:
1. Attacker administers a GitHub App installed on `attacker-org`, tracked by a shared Shipit instance, and knows `attacker-org`'s `webhook_secret`.
2. Shipit also tracks `victim-org/victim-repo` (registered by a different tenant on the same instance).
3. Attacker crafts a raw JSON body:
```json
{"sha": "<victim-commit-sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org-secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves org `attacker-org`, verifies successfully (own secret matches own signature). `StatusHandler` then writes a fabricated `success` status on `victim-org/victim-repo`'s commit via `Commit.where(sha:).create_status_from_github!`, since the commit lookup by SHA has no repository scoping either. [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
