### Title
Cross-organization webhook forgery via signature/action field mismatch in `WebhooksController` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate a webhook against using the payload's `repository.owner.login` (or `organization.login`), but every event `Handler` that subsequently acts on the payload resolves its target `Stack` using an entirely different field: `repository.full_name`. Because the field that is cryptographically bound to the signature check is not the same field the handlers use to select which `Stack`/`Repository` to mutate, a party who legitimately controls the webhook secret for one configured GitHub organization can forge a payload whose `repository.full_name` points at a stack belonging to a *different* organization hosted on the same Shipit instance, and have that forged event processed as if it were authentic.

### Finding Description
`verify_signature` computes `repository_owner` from the raw payload and fetches the corresponding `GitHubApp` config to validate `X-Hub-Signature`: [1](#0-0) [2](#0-1) 

Once the signature check passes for that organization, `create` dispatches the *same raw payload* to every registered `Shipit::Webhooks` handler for the event, unmodified: [3](#0-2) 

Every handler (`push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, etc.) inherits `Handler#stacks`, which resolves the target `Repository`/`Stack` from `repository.full_name`, a field that was never checked against the organization whose secret validated the request: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this attacker-controlled string on `/` and looks up any repository record by owner/name, with no relation to `repository_owner`/`organization.login`: [5](#0-4) 

The trust binding that should hold is:
```
organization whose webhook_secret validated the request == organization of the repository the handler acts upon
```
This binding is never enforced. `repository.owner.login`/`organization.login` (covered by the signature check) and `repository.full_name` (used to select the acted-upon `Stack`) are independent, attacker-controllable strings inside the same signed JSON body — the signature only proves "this body was produced by whoever knows Org A's webhook secret", not "this body only references Org A's resources".

This is the direct analog of the reported `collectFees` reentrancy bug: there, the fee-transfer/accounting step could be re-triggered without being bound to a single authoritative check of the fee counter, letting a party with a limited, legitimate role (a "host") drain funds belonging to others. Here, a party with a limited, legitimate role (an org admin who configures their own GitHub App and therefore knows its `webhook_secret`) can perform a validated action (`verify_signature` passes) whose real-world effect (`repository.full_name`-scoped mutation) is not actually covered/bound by that validation, letting them act on another organization's stack.

### Impact Explanation
Shipit is explicitly designed to host multiple organizations' repositories from one instance (`config/secrets.development.shopify.yml` shows the `github: { org1: {...}, org2: {...} }` multi-org config), each with its own `webhook_secret`. Any org admin onboarded this way legitimately knows their own org's `webhook_secret` (they configure it in their own GitHub App settings). Using that secret, they can sign an arbitrary JSON body and set `repository.full_name` to point at a victim stack belonging to an unrelated organization on the same instance:

- Via the `status` event handler, they can post arbitrary commit statuses (`success`/`failure`) for arbitrary commit SHAs of the victim's stack. Since Shipit gates deploys on commit status checks, injecting a fabricated `success` status for a commit that never actually passed CI directly enables an **unauthorized deploy** of that commit — matching the "Critical: unauthorized deploy" impact bucket defined in scope.
- Via `push`/`check_suite` handlers, they can force sync jobs and check-run refreshes against a victim's stack, effectively puppeting stack state and Merge Queue behaviour they have no authorization over.

### Likelihood Explanation
Requires no session, `ApiClient` token, GitHub App private key, or privileged Shipit account — only the `webhook_secret` of any single GitHub organization already configured on the shared Shipit instance, which that organization's own administrator legitimately possesses. This matches the "unprivileged attacker" framing of the source report (a "malicious host" abusing a role that is legitimate for their own resources but not others').

### Recommendation
Bind the same field on both sides of the check: after `verify_signature` establishes which organization's secret validated the request, every handler's `stacks`/`repository_name` lookup should assert that the resolved `Repository#owner` equals the verified `repository_owner` (or `organization.login`), rejecting the event (or scoping the lookup to that owner) otherwise, rather than trusting `repository.full_name` independently of the value used for signature selection.

### Proof of Concept
1. Shipit is configured for two orgs, `org-a` and `org-b`, each with its own `github.webhook_secret` (as in `config/secrets.development.shopify.yml`). Attacker administers `org-a` and knows `org-a`'s `webhook_secret`. `org-b` hosts a victim stack `org-b/victim-repo` with deploys gated by CI status checks.
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<victim commit sha awaiting CI>",
     "state": "success",
     "context": "ci/build",
     "repository": { "full_name": "org-b/victim-repo", "owner": { "login": "org-a" } }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"org-a"` (from `repository.owner.login`), fetches `org-a`'s `GitHubApp`, and the signature validates successfully. [1](#0-0) 
5. `Shipit::Webhooks.for_event('status')` dispatches to `Shipit::Webhooks::Handlers::StatusHandler`, which (via the inherited `Handler#stacks`/`repository_name`) resolves the target repository from `repository.full_name = "org-b/victim-repo"`, not `"org-a"`. [4](#0-3) 
6. A forged `success` status is recorded against the victim's commit, satisfying Shipit's CI-gating and enabling an unauthorized deploy of that commit on `org-b`'s stack — despite the request only ever being authenticated as belonging to `org-a`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
