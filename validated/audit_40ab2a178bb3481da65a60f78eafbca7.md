### Title
Cross-organization webhook signature confusion allows forged commit statuses / CI bypass on another organization's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` is used to validate the inbound HMAC based on a field taken from the untrusted JSON body itself, while the event handlers resolve the *target* repository/stack from a **different** field of that same body. Nothing ties the two together, so a validly-signed webhook (signed with an attacker-controlled organization's own, legitimately-known secret) can name an entirely different organization's repository as the target of the event.

### Finding Description
`verify_signature` derives the signing organization exclusively from the payload: [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This value is used only to pick the `Shipit.github(organization:)` app/secret that verifies `X-Hub-Signature`: [2](#0-1) 

Once the signature check passes, every event handler resolves the actual `Stack`/`Repository` to act on from a **different** field of the same JSON body — `repository.full_name` — via `Handler#stacks`/`#repository_name`: [3](#0-2) 

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the stack that gets acted on) are two independent, attacker-controlled keys inside the same "repository" object of the raw POST body. Nothing enforces that `full_name` is prefixed by `owner.login`, or that the resolved `Repository`/`Stack` actually belongs to the organization whose secret validated the signature.

Because a webhook is only cryptographically bound to *whichever* org's secret was chosen at verification time — not to the org that actually owns the repository named in `full_name` — an attacker who legitimately administers a GitHub organization/repo integrated with this Shipit instance (and therefore genuinely knows their own org's `webhook_secret`) can craft a request such as:

```json
{
  "action": "success",
  "sha": "<sha of a commit that exists on victim-org/victim-repo>",
  "state": "success",
  "context": "required-ci-check",
  "target_url": "https://attacker.example/fake",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```

`verify_signature` validates this against `attacker-org`'s secret (which the attacker legitimately possesses) and passes. The downstream handler then resolves the *stack* via `full_name = "victim-org/victim-repo"`, i.e. a stack the attacker does not control, and processes the event against it — e.g., appending a commit status, or (for `push`) enqueuing `GithubSyncJob` for the victim stack.

### Impact Explanation
Shipit's deploy gating relies on commit CI statuses reported through this webhook path — `deploy_spec.required_statuses` / `blocking_statuses` gate whether a commit is deployable: [4](#0-3) 

Because the `commit_status`/`status` event is one of the handled webhook events and (per this engine's own tests) directly persists attacker-supplied `state`/`context`/`target_url`/`description` onto the matched commit's statuses, an attacker who owns a legitimately-integrated organization can forge a passing status for a *required* CI context on a victim organization's stack, which is exactly the kind of trust-boundary confusion that lets a signature-verified-but-misdirected payload cause writes/state changes against a repository the sender does not own — enabling an authorized-but-CI-gated deployer to ship an otherwise non-deployable commit on the victim stack. This crosses the "cross-repository writes" / "unauthorized deploy" bar because the write is attributed to, and trusted by, a repository/stack the attacker never proved ownership of.

### Likelihood Explanation
Exploitation requires only that the attacker legitimately controls *any one* GitHub organization/repository already integrated with the same multi-tenant Shipit instance (a routine, low-privilege situation for public Shipit deployments serving many orgs/teams) — no `webhook_secret`, `api_clients_secret`, `GITHUB_TOKEN`, or Shipit session for the *victim* org is ever required, satisfying the "unprivileged attacker" bar. The victim commit sha and repo full_name are typically public/guessable (GitHub commit SHAs and repo names are not secrets).

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), cross-validate that the organization/owner used to select the verifying secret matches the owner segment of `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers, rejecting the webhook with 422 on mismatch. Alternatively, resolve the target `Repository`/`Stack` using the *same* field that was authenticated (`repository.owner.login`) rather than an independent `full_name` field.

### Proof of Concept
1. Attacker legitimately administers `attacker-org` integrated with this Shipit instance and knows `attacker-org`'s `webhook_secret`.
2. Attacker sends `POST /webhooks` with `X-Github-Event: status`, HMAC-signed with `attacker-org`'s secret over a body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"` and `sha` is a real commit sha on the victim stack.
3. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the signature successfully because it only checks against `attacker-org`'s secret.
4. The status handler resolves the target stack via `Handler#stacks`/`#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which reads `repository.full_name`, landing on the victim's stack, and records the forged status against the victim's commit — despite the request never being validated by, or attributable to, `victim-org`.

Note: I was unable to retrieve the exact source of the `status`/`commit_status` handler file (only its test-observed behavior via `test/controllers/webhooks_controller_test.rb`) within the available index; a Devin session with full repository access would be needed to confirm the precise persistence code path and whether any additional scoping by `full_name` is applied before the `Status` record is written.

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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
