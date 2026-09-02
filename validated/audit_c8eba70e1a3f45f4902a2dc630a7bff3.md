### Title
Webhook signature verified against one GitHub organization while payload actions (repository resolution / commit status writes) are not bound to that organization — cross-repository/cross-organization write - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The analog of the VToken bug class here is a mismatch between the credential-checked field and the field actually acted upon. `WebhooksController` verifies the HMAC signature of a webhook using the GitHub organization derived from `repository.owner.login` in the JSON body, but the code that subsequently processes the same body (in particular `StatusHandler`) never re-validates that the object being mutated (a `Commit`, resolved only by `sha`, with no repository/organization scoping at all) belongs to that authenticated organization.

### Finding Description
`WebhooksController#verify_signature` selects which organization's webhook secret to check the signature against using an attacker-controlled JSON field: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Once the signature is accepted (using the secret belonging to whatever organization `repository.owner.login` names), the raw JSON body is handed unmodified to the registered handler for the event: [3](#0-2) 

`StatusHandler`, invoked for `status` events, does not consult `repository.owner.login` or `repository.full_name` at all — it looks up commits purely by `sha` across the entire database and writes a CI status onto whatever `Commit` rows match: [4](#0-3) 

More generally, the base `Handler` class resolves the repository to act on from `payload.dig('repository', 'full_name')`, a completely separate JSON key from the one used for signature-org selection (`repository.owner.login`), with no cross-check that the two agree: [5](#0-4) 

This breaks the binding: `organization whose secret authenticated the request == organization/repository that the handler mutates`. In a Shipit deployment configured with multiple GitHub organizations (`Shipit.github(organization: ...)` supports per-org config/secrets, per `lib/shipit/github_app.rb`), an actor who legitimately controls the webhook secret for Organization A (e.g. is an admin of an org/repo onboarded onto the same Shipit instance) can hand-craft an arbitrary JSON body, sign it with Organization A's own secret, but populate `repository.full_name` or an unrelated `sha` value corresponding to a commit that belongs to Organization B's repository. Because the HMAC only proves "this body was signed with Org A's secret," and never that the body's content is scoped to Org A, the handler ends up executing on Org B's data.

The `status` handler is the sharpest instance of this: it does not use the repository object from the payload whatsoever, so a valid status-webhook signature from *any* onboarded organization allows forging a green CI status against any commit SHA known to exist in the entire Shipit instance, regardless of which repository or organization actually owns that commit.

### Impact Explanation
Shipit uses GitHub commit statuses as safety-check gates before allowing a deploy (a commit must show a passing/green CI status to be considered deployable). By forging a `status` webhook that is validly signed with one organization's webhook secret but targets a commit belonging to a different repository/organization tracked by the same Shipit instance, an attacker can mark that foreign commit as `success`, satisfying Shipit's CI-status safety gate for a stack they otherwise have no write access to. This is a cross-repository write of protected state (CI status) that gates deploy safety checks, matching the "cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Exploitation requires the attacker to already control (or be an authorized webhook sender for) at least one organization/repository onboarded to the same multi-tenant Shipit instance — this is a realistic and unprivileged-relative-to-other-tenants scenario in any Shipit deployment serving more than one GitHub org, since organizations are typically onboarded independently and each org admin only needs to know their own webhook secret to satisfy `verify_webhook_signature`. No access to the victim org's secret, no Shipit session, and no `ApiClient` token are required — only knowledge of one's own organization's `webhook_secret`, which by design is distributed to every onboarded org's webhook configuration.

### Recommendation
After signature verification succeeds for organization X, re-validate that every repository-identifying field used downstream (`repository.full_name`, and for `StatusHandler`, the resolved `Commit#github_repo_name`) actually belongs to organization X before any handler is allowed to mutate state. Concretely: derive the repository/organization from the same value used for `verify_signature`, and in `StatusHandler#process`, filter `Commit.where(sha: params.sha)` by the commit's repository owner matching the authenticated organization, rejecting/no-op-ing any mismatch.

### Proof of Concept
1. Attacker owns/administers "org-attacker" webhook config on the shared Shipit instance, and thus knows `webhook_secret_attacker`.
2. Attacker crafts a `status` event payload:
```json
{
  "sha": "<sha_of_commit_in_victim_org_repo>",
  "state": "success",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_attacker, body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "org-attacker")` and successfully verifies the signature against `webhook_secret_attacker`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim organization's commit (no owner/org filter applied), and calls `commit.create_status_from_github!(params)`, marking it `success` — even though the request was never authenticated for the victim's organization.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
