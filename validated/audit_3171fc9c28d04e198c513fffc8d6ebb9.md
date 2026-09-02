### Title
Webhook signature verification authenticates the wrong entity — an attacker who knows the webhook secret of *any* onboarded GitHub organization can forge CI status / push / check-suite events for *any other* organization's repositories, unlocking unauthorized deploys - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) to validate an inbound webhook against using a field taken from the *unverified* request body itself, then hands the same unverified body to handlers that act on a completely different field of that body (or, in the `status` event's case, on no repository-scoping field at all). Because nothing binds "the organization whose secret validated the signature" to "the repository/commit the handler subsequently mutates," an attacker who is a legitimate, low-privilege operator of one Shipit-onboarded GitHub organization (and therefore knows *that* organization's webhook secret) can forge events that Shipit will apply to a different organization's stacks and commits.

### Finding Description
The signature check derives the signing organization exclusively from the payload: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

`repository_owner` is read straight from the JSON body being validated — it is not an independent, trusted channel (e.g. it isn't derived from the URL, from a per-organization webhook route, or from GitHub App installation metadata). It is only *self-consistent* for genuine GitHub-issued payloads because GitHub itself always sets `repository.owner.login` to match the owner segment of `repository.full_name`. Nothing in Shipit enforces that consistency for a forged, attacker-crafted body.

Once the signature is judged "verified" (because it matches whichever organization the attacker chose via `repository_owner`), the raw params are dispatched unchanged to handlers: [3](#0-2) 

Handlers resolve the actual target using a *different* field of the same untrusted body: [4](#0-3) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the repository whose stacks get mutated) are two independent keys inside one attacker-controlled JSON document — there is no cross-check that they agree.

The `status` handler is even more exposed: it does not scope by repository at all, it matches by SHA across the entire Shipit database: [5](#0-4) 

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

So the binding actually enforced is: `signing_secret_matches(repository_owner_field) == true`, while the binding that should be enforced (and is broken) is: `organization_that_signed == organization_that_owns(repository_name_or_commit_being_mutated)`.

### Impact Explanation
Any attacker who legitimately administers one GitHub organization onboarded to a multi-tenant Shipit instance (and therefore knows that organization's own `webhook_secret`, a value they are entitled to know) can:
1. Craft a `status` webhook body with `repository.owner.login` set to *their own* organization (so the HMAC computed with their known secret validates), but with `sha` set to the SHA of a commit belonging to a *victim* organization's stack, and `state: "success"`, `context: "<required-CI-context>"`.
2. Because `StatusHandler` queries `Commit.where(sha: params.sha)` with no ownership check, this creates a green, required CI status on the victim's commit — the exact signal `ci.require` in `shipit.yml` uses to unblock the **Deploy** button — enabling an unauthorized deploy of that commit by anyone who subsequently uses Shipit's UI/API, without ever needing the victim organization's webhook secret, ApiClient token, GitHub write access, or private key.
3. Similarly, `PushHandler`/`CheckSuiteHandler` can be triggered against a victim's `Repository`/`Stack` records (resolved via `full_name`) despite the request being signed only by the attacker's own organization's secret, forcing `stack.sync_github` or check-run refresh cycles on stacks they have no authorization over.

This crosses the "authentication bypass" / "unauthorized deploy" threshold explicitly listed as in-scope Critical impact, since the entity that GitHub authenticated (the attacker's own org, via its own webhook secret) is not the entity whose data gets mutated (the victim's commit/stack).

### Likelihood Explanation
Requires only that Shipit onboard more than one GitHub organization (a supported, documented configuration — see `README.md`/`docs/setup.md` describing multiple `secrets.yml` GitHub app entries and `Shipit.github(organization:)` indifferent lookup) and that the attacker legitimately control one of those organizations (a normal "regular customer" attacker, not a Shipit admin, not holding any victim credentials). No social engineering, TLS interception, or privileged account is required — only crafting a JSON body and computing an HMAC with a secret the attacker is entitled to know.

### Recommendation
Bind the organization that produced a valid signature to the resource actually being acted upon before dispatching to handlers:
- After `verify_signature` succeeds, re-derive the acting organization from the *same trusted variable already used for signing* (`repository_owner`) and pass it explicitly into handlers, rejecting any event whose `repository.full_name` owner segment, or whose target `Commit`'s repository owner, does not match `repository_owner`.
- In `StatusHandler`, scope the `Commit` lookup by the repository derived from the verified organization (e.g. join through `Repository`/`Stack` filtered by `repository_owner`) instead of an unscoped `Commit.where(sha:)`.
- Consider deriving the signing organization from a stable, non-attacker-controlled channel (e.g. distinct webhook URLs per organization/installation, or the GitHub App installation ID from headers) rather than from a field embedded in the JSON payload being verified.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `attacker-org` (attacker is a legitimate admin, knows its `webhook_secret`) and `victim-org` (unrelated, higher-value org with an existing `Stack` and a `Commit` whose `sha` is `deadbeef...` and which requires CI context `ci/required`).
2. Attacker builds the JSON body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/whatever"},
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required",
  "branches": [{"name": "main"}]
}
```
3. Attacker computes `sha1=HMAC(webhook_secret_of_attacker_org, raw_body)` and sends `POST /webhooks` with `X-Github-Event: status` and `X-Hub-Signature` set to that value.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully with the attacker's own secret [1](#0-0) .
5. `StatusHandler#process` finds the victim's `Commit` by `sha` alone (ignoring which org signed the request) and records a green `ci/required` status on it [5](#0-4) , satisfying `victim-org`'s deploy CI gate without any credential belonging to `victim-org`.

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
