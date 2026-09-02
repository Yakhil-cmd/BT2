### Title
Webhook signature verifies the sending organization, but `StatusHandler` writes commit statuses with no binding to that organization's repositories - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to authenticate a webhook delivery from the *sending organization*, but the `status` event handler that mutates data never checks that the commit it updates actually belongs to a repository owned by that organization. This breaks the binding: `organization that authenticated == repository that is written`.

### Finding Description
The controller verifies the HMAC signature using a webhook secret selected purely from an attacker-controlled JSON field: [1](#0-0) [2](#0-1) 

`repository_owner` only determines *which organization's secret* must match the signature - it says nothing about which repository the event's payload is allowed to affect. Once the signature check passes for organization X, the full unrestricted `params` are dispatched to every registered handler for the event type: [3](#0-2) 

Most handlers correctly re-derive the affected repository from the payload and scope their side effects to that repository's stacks, via `Handler#stacks`/`#repository_name`: [4](#0-3) 

`StatusHandler`, however, does not use `stacks`/`repository_name` at all. It mutates state purely by commit SHA, globally, across the entire `commits` table, with no repository or organization scoping whatsoever: [5](#0-4) 

Because a valid signature only proves "this payload was signed with organization X's `webhook_secret`" - and says nothing about which repository/commit the payload names - an attacker who legitimately controls delivery of `status` webhooks for **any one** organization configured in this Shipit instance (e.g., their own GitHub App installation on Org A, one of potentially many orgs configured under `Shipit.github` per `docs/setup.md`'s "Using Multiple Github Applications" section, or any org left with a blank `webhook_secret`) can submit a `status` event whose `sha` field names a commit belonging to an entirely different, unrelated repository/stack (Org B), and have `Commit.create_status_from_github!` apply that (fabricated) status to Org B's commit - despite never having any relationship to Org B's repository.

### Impact Explanation
This is a cross-repository write: an attacker authorized only for organization A's webhooks can forge a passing (or failing) CI status onto any commit in organization B's stacks tracked by the same Shipit instance, as long as they know/guess the target SHA (commit SHAs are public GitHub data). Shipit stacks use recorded commit statuses to gate continuous deployment and merge-queue behavior (`ci.require`, `merge_queue_enabled`, etc., per `README.md`). Forging a "success" status on a commit can therefore make an otherwise CI-blocked commit eligible for automatic deploy or merge - an unauthorized deploy/merge triggered purely by exploiting the org-vs-repo binding gap, satisfying the "unauthorized deploy, rollback or merge" High/Critical impact bar without any Shipit session, API token, or write access to the target repository.

### Likelihood Explanation
Low-to-moderate: requires the attacker to control (or have delivery access to) a legitimately configured GitHub App/organization already registered in this specific Shipit instance's `Shipit.github` multi-org config (a realistic scenario for larger deployments tracking several organizations, as documented in `docs/setup.md`), or to find an organization configured with a blank `webhook_secret` (which `verify_webhook_signature` treats as "always verified" - see `lib/shipit/github_app.rb:76-83`). The target commit SHA must also be known, which is trivially available from public GitHub history.

### Recommendation
Scope `StatusHandler#process` (and any other handler that mutates by cross-cutting identifiers such as SHA) to the repository actually named in the *same verified organization's* payload, e.g. by joining through `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` and restricting the `Commit` lookup to that repository's stacks, mirroring `Handler#stacks`. Additionally, `verify_signature` should assert that the organization used to select the secret is consistent with the repository owner referenced by the handler's own repository-resolution logic, so a payload cannot claim org X for authentication while acting on org Y's data.

### Proof of Concept
1. Configure/observe that this Shipit instance tracks multiple GitHub orgs (`Shipit.github` multi-org config) - attacker controls delivery/signing for Org A only, and Org B (unrelated) has a tracked stack/commit with known SHA `abc123`.
2. Attacker computes `sha256=<hmac>` using Org A's `webhook_secret` over a JSON body:
   ```json
   { "sha": "abc123", "state": "success", "context": "ci/required-check",
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/whatever"} }
   ```
3. POST to `/github/webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha256=<hmac>`.
4. `verify_signature` looks up Org A's app via `repository_owner` (`"OrgA"`) and validates successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` runs `Commit.where(sha: "abc123")` — matching Org B's commit regardless of the signed org — and calls `create_status_from_github!`, injecting a forged "success" status onto Org B's commit (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), potentially unblocking an automatic deploy/merge on Org B's stack.

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
