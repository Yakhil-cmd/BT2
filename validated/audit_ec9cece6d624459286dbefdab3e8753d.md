### Title
Webhook organization spoofing via divergent owner-resolution paths enables cross-organization stack mutation - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#repository_owner` selects the GitHub organization used for HMAC verification from `params.dig('organization', 'login')` when `repository.owner.login` is absent, while the event handler (e.g. `ClosedHandler`) resolves the target repository independently from `repository.full_name`. Because these two values are read from different, attacker-controllable JSON paths in the same request body, an attacker who controls (or who can send unsigned/weakly-signed traffic for) any organization onboarded to the Shipit instance can craft a payload that verifies against that organization's secret while mutating a different organization's stack.

### Finding Description
The broken binding is: `organization used by verify_signature to select the HMAC secret == organization that owns the repository the handler subsequently mutates`. This does not hold.

`repository_owner` computes the signing organization as:
```
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [1](#0-0) 

`verify_signature` then fetches the `GitHubApp` for that owner and checks the signature against the *entire* raw body:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

`GitHubApp#verify_webhook_signature` HMACs the raw bytes with that organization's own `webhook_secret`, and critically returns `true` unconditionally if no secret is configured for that organization:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Meanwhile, the `pull_request.closed` handler resolves the repository to mutate purely from `repository.full_name`, and its `ExplicitParameters` schema only requires `repository.full_name` — it does **not** require `repository.owner.login`:
```
requires :repository do
  requires :full_name, String
end
...
def repository
  @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
``` [4](#0-3) 

The base `Handler` class likewise derives `repository_name` from `payload.dig('repository', 'full_name')`, independent of `repository_owner`: [5](#0-4) 

**Exploit flow:** Attacker POSTs to `/webhooks` with `X-Github-Event: pull_request` and a body such as:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": {"id":1,"number":1,"url":"...","title":"x","state":"closed","additions":0,"deletions":0,
    "head":{"sha":"x","ref":"x"}, "user":{"login":"attacker"}, "assignees":[], "labels":[]},
  "repository": {"full_name": "victim-org/repo"},
  "organization": {"login": "attacker-org"},
  "sender": {"login": "attacker"}
}
```
Because `repository.owner.login` is absent, `repository_owner` returns `attacker-org`, so `verify_signature` checks the HMAC against `attacker-org`'s `GitHubApp#webhook_secret` (which the attacker, as an admin of the legitimately onboarded `attacker-org`, knows — or, if unset, is bypassed entirely per line 77 of `github_app.rb`). The signature check passes, and `Shipit::Webhooks.for_event('pull_request')` dispatches to `ClosedHandler`, which parses `repository.full_name` as `victim-org/repo` and calls `review_stack.archive!` on `victim-org`'s repository/stack.

No existing guard closes this gap: `drop_unhandled_event` only checks the event name is registered; `ExplicitParameters` for `ClosedHandler` never requires `repository.owner.login` to match the signing organization; there is no cross-check between `repository_owner` (used for auth) and `repository.full_name` (used for the mutation).

### Impact Explanation
An attacker who administers (or can send traffic for) any organization onboarded to a shared/multi-tenant Shipit instance can forge webhook events that are authenticated against their own organization's secret (or against no secret at all, if unset) but that mutate the stack/review-stack state of an arbitrary victim organization's repository — e.g., archiving a victim's review stack via `ClosedHandler`, or triggering other repository-scoped side effects in other `pull_request`/`push`/`status` handlers that similarly key off `repository.full_name`. This is a cross-repository/cross-tenant write authorized only by the attacker's own organization signature, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any victim repository known to the attacker and any onboarded organization with a known-or-absent secret.

### Likelihood Explanation
Preconditions: the Shipit instance must host multiple organizations (multi-tenant), the attacker must control or know the webhook secret of at least one onboarded organization (or that organization must have no `webhook_secret` configured, which `verify_webhook_signature` explicitly tolerates), and the victim organization/repository must be known and present in the Shipit database with review stacks. Given these, exploitation cost is a single crafted HTTP POST with a valid HMAC computed with a secret the attacker legitimately possesses (their own org's) — no privileged Shipit session, API token, or GitHub App private key is required. This is realistic in shared/self-service Shipit deployments where multiple GitHub organizations are independently onboarded.

### Recommendation
Make `repository_owner` and the handler's repository resolution consistent and mutually validated: derive the signing organization strictly from the same `repository.full_name`/`repository.owner.login` used by the handler (do not fall back to `organization.login` for owner-authentication purposes), and additionally verify, after signature check, that the resolved `repository.full_name`'s owner matches the organization whose secret verified the signature. Reject the webhook if they diverge.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, not included per scope but described):
1. Configure two organizations in `Shipit.github_apps`-style config: `attacker-org` (with a known test `webhook_secret`, e.g. `"attacker-secret"`) and `victim-org` (with its own distinct secret).
2. Create a `Shipit::Repository` for `victim-org/repo` with an existing review stack tracking PR #1.
3. Build a JSON body identical to the exploit payload above, with `repository.full_name = "victim-org/repo"` and `organization.login = "attacker-org"` and no `repository.owner.login`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', "attacker-secret", body)`.
5. POST to `/webhooks` with `X-Github-Event: pull_request` and the computed signature.
6. Assert: response is `200 OK` (signature accepted using `attacker-org`'s secret) AND `victim-org`'s review stack for PR #1 is archived (state changed) — i.e., assert `attacker_secret_hmac == accepted_signature` (attacker-org's HMAC accepted) while `victim_org_repo.stacks.reload.first.archived? == true`, proving the organization that authenticated the request (`attacker-org`) differs from the organization whose stack was mutated (`victim-org`).

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-53)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
