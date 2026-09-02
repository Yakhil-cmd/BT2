### Title
Webhook signature is verified against an organization derived from the unverified payload, letting one onboarded organization forge webhook events for another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App / HMAC secret to check against by reading `repository_owner` out of the still-unverified JSON body, then verifies the *raw body* against that org's secret. Once verification succeeds, `create` dispatches the exact same raw body to event handlers that look up the target `Stack`/`Repository` using a *different* field of that same untrusted body (`repository.full_name`). Nothing binds "the organization whose secret validated this request" to "the repository the handler acts on" — the same JSON payload supplies both, but the app never cross-checks them.

### Finding Description
`verify_signature` picks the verifying `GitHubApp` using attacker-influenced data before any cryptographic check occurs: [1](#0-0) [2](#0-1) 

In a multi-organization deployment (documented and supported via `secrets.github.<org>` blocks, each with its own `webhook_secret`), `Shipit.github(organization:)` resolves a distinct `GitHubApp`/secret per organization key: [3](#0-2) 

The handler dispatch, however, resolves the target `Stack`/`Repository` from a *different* field of the same body — `repository.full_name` — completely independent of which organization's secret validated the request: [4](#0-3) [5](#0-4) [6](#0-5) 

Because `repository.owner.login` (used for signature-org selection) and `repository.full_name` (used for the actual repository/stack lookup) are just two independent string fields inside the same attacker-controlled JSON body, an organization that legitimately controls its own GitHub App/webhook secret (Org A, onboarded per the documented multi-org config) can craft a webhook payload where:
- `repository.owner.login` = `"OrgA"` (or `organization.login` = `"OrgA"` for events without a `repository` key, e.g. `membership`) — so `verify_signature` picks Org A's `GitHubApp` and the HMAC (signed with Org A's own, legitimately-known `webhook_secret`) validates successfully.
- `repository.full_name` = `"OrgB/some-target-repo"` — so the dispatched handler operates on Org B's `Stack`/`Repository`, an organization the requester never authenticated for.

This is exactly the "organization that authenticated versus the repository that is written" binding called out as a valid analog class: the equality `authenticated_org == acted_on_repo.owner` is assumed but never enforced.

### Impact Explanation
Handlers reachable this way include `PushHandler` (triggers `stack.sync_github(expected_head_sha: …)` on Org B's stack with an attacker-chosen `after` SHA, driving `GithubSyncJob`), `CheckSuiteHandler` (forces check-run refresh on Org B's commits), `StatusHandler` (injects arbitrary commit statuses via `create_status_from_github!`, which can flip CI gating used by the merge queue/continuous deployment), and the `PullRequest` handlers (`OpenedHandler`/`ClosedHandler`, etc., which provision or archive Org B's review stacks). Because `StatusHandler` lets an unrelated org write fabricated CI status ("success"/failure, arbitrary `context`) onto Org B's commits, and Shipit's continuous-delivery / merge-queue logic gates on commit `deployable?`/status checks, this can be leveraged to unlock or block deploys/merges on a stack the requester does not own — an unauthorized cross-repository action satisfying the "unauthorized deploy/merge" bar. This qualifies as **Critical** to **High** depending on which handler chain is exercised (cross-org stack manipulation, forged CI status feeding into deploy/merge gating).

### Likelihood Explanation
This requires an attacker who is a legitimate, onboarded organization in a multi-organization Shipit deployment (i.e., they know their own org's real `webhook_secret`, which they set up themselves per `docs/setup.md`'s "Using Multiple GitHub Applications" section) but is targeting a *different* onboarded organization's repositories/stacks on the same shared Shipit instance. This is plausible in shared/multi-tenant Shipit installations and requires no compromise of GitHub, no session, and no `ApiClient` token — only the ability to POST directly to `/webhooks` with a body whose `repository`/`organization` fields diverge from what a real GitHub delivery for that org would ever send (GitHub always keeps these fields internally consistent; only a direct, spoofed HTTP request to Shipit's public `/webhooks` endpoint from outside GitHub can produce this divergence).

### Recommendation
Do not select the verifying `GitHubApp`/secret from unverified payload data that differs from the field later used to resolve the acted-upon resource. Concretely:
- After parsing `repository.full_name` (or `organization.login`), look up the target `Shipit::Repository`/`Stack` first, derive its *canonical* owning organization from the stored record, and verify the signature using that stack's own configured `GitHubApp`/secret — not a value taken fresh from the same untrusted body.
- Alternatively, verify that `repository.owner.login` (or `organization.login`) used for signature selection exactly matches the owner segment of `repository.full_name` before proceeding, rejecting mismatches with 422.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub App config, e.g. `secrets.github.OrgA` and `secrets.github.OrgB`, each with a distinct `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. As an operator/admin of OrgA (who legitimately knows OrgA's `webhook_secret` because they configured their own GitHub App), craft a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and send `X-Github-Event: push`.
4. In `verify_signature`, `repository_owner` resolves to `"OrgA"`; `Shipit.github(organization: "OrgA").verify_webhook_signature` succeeds because the HMAC was computed with OrgA's real secret over this exact body.
5. `create` dispatches the parsed body to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("OrgB/target-repo")` [7](#0-6)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on OrgB's stack [8](#0-7) , despite the request never having been authenticated as belonging to OrgB.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
