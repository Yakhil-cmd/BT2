### Title
Cross-organization signature confusion in `pull_request`/`labeled` webhook — verifier selection (`repository_owner`) diverges from handler's repository target (`repository.full_name`) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#repository_owner` selects which organization's `webhook_secret` verifies the inbound signature by first reading `repository.owner.login` and only falling back to `organization.login` if that's absent, while `LabeledHandler` independently resolves the target repository purely from `repository.full_name`, which is not required to reference the same org as `repository.owner.login`/`organization.login`. Because the `ExplicitParameters` schema for `LabeledHandler` only requires `repository.full_name` and never validates that it belongs to the org used for signature verification, an attacker who controls one legitimately-onboarded organization (Org A, whose `webhook_secret` they know because they configured that org's Shipit integration themselves) can sign a payload whose `repository.full_name` points at a victim organization's repo (Org B), causing `LabeledHandler` to archive/unarchive Org B's review stack.

### Finding Description
The broken binding, stated as an equality that the code must (but does not) enforce:
`organization_that_signed_the_request == organization_that_owns(repository.full_name_used_by_handler)`

Trace:
1. `WebhooksController#verify_signature` selects the verifying org via:
`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) 
and then verifies the signature against that org's `webhook_secret` via `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [2](#0-1) 

2. `LabeledHandler`'s `ExplicitParameters` schema requires `repository.full_name` to exist, but does not require or cross-check `repository.owner.login` against it: [3](#0-2) 

3. The handler resolves the actual repository/stack to mutate solely from `params.repository.full_name`, independent of whatever value verified the signature: [4](#0-3)  and then archives/unarchives that repo's review stack based on the label: [5](#0-4) 

Exploit: an attacker who administers Org A on GitHub (and therefore configured/knows Org A's `webhook_secret` in Shipit) crafts a JSON body where `repository.full_name = "OrgB/victim-repo"` but omits `repository.owner.login`, and sets `organization.login = "OrgA"`. `repository_owner` falls back to `"OrgA"`, so `verify_signature` checks the signature against Org A's secret — which the attacker legitimately has — and the request passes. `LabeledHandler` then loads the repository/stack for `OrgB/victim-repo` and calls `stack.archive!`/`stack.unarchive!` based on the label present in the same attacker-controlled payload.

This bypasses the implicit trust assumption that "whichever secret verified the payload also authorizes the payload's repository content," because the controller and the handler read the identifying repository information from two independently-settable JSON paths, and the parameter schema never ties them together.

### Impact Explanation
An attacker who legitimately controls a single onboarded organization can mutate the review-stack state (archive/unarchive) of any other organization's repository whose full name they can guess or discover, without ever touching that victim org's `webhook_secret`. This is a cross-tenant state manipulation: one repository's authenticated payload writes another repository's records, matching the "Critical" category (payload for one repository mutating another's stack) in the target list.

### Likelihood Explanation
Preconditions: Shipit must be configured to serve multiple GitHub organizations (each with a distinct `webhook_secret`), and the attacker must control (i.e., have legitimately onboarded) at least one such organization so they know its `webhook_secret` and can produce a valid `X-Hub-Signature`. Given that, the attacker needs only to know or guess the victim's `owner/repo` full name, craft a JSON body omitting `repository.owner.login`, and send one POST to `/webhooks`. This is inexpensive, fully attacker-scripted, and repeatable against any repository whose full name they know, as long as review stacks are enabled for that repository.

### Recommendation
In `LabeledHandler` (and other webhook handlers reading `repository.full_name`), require and validate `repository.owner.login` and ensure it matches the value actually used by `WebhooksController#repository_owner` to select the verifying `webhook_secret`. Alternatively, have `verify_signature` derive the organization strictly and consistently from the same field the handlers use (`repository.full_name`'s owner segment), removing the `organization.login` fallback entirely, or pass the verified organization login into the handler and assert it matches `repository.full_name`'s owner before performing any mutation.

### Proof of Concept
minitest (`ActionDispatch::IntegrationTest`) plan:
1. Configure two orgs in test secrets: `org_a` with a known `webhook_secret_a`, and `org_b` with its own repo/stack (`org_b/victim-repo`) with review stacks enabled and a provisioning label configured.
2. Build a `pull_request`/`labeled` JSON payload with `repository: { full_name: "org_b/victim-repo" }` (no `owner` key), `organization: { login: "org_a" }`, and a `pull_request.labels` array containing the provisioning label to trigger `archive?`/`unarchive?`.
3. Sign the raw body with `webhook_secret_a` and set `X-Hub-Signature` and `X-Github-Event: pull_request` headers.
4. POST to `/webhooks`; assert response is `200 OK` (verification passed using org_a's secret).
5. Assert equality check both sides: before request, `Repository.from_github_repo_name("org_b/victim-repo").review_stacks.first.archived?` is one value; after the request it flips — proving org_a's signature authorized a mutation on org_b's stack, i.e., `verifying_org ("org_a") != owning_org("org_b")` yet the write succeeded.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
