### Title
Webhook signature is verified against the org named in `repository.owner.login`, while handlers act on the unrelated `repository.full_name` field, letting a low-privilege GitHub org owner forge deploy-relevant events for another tenant's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit.github_organizations` and `Shipit::GitHubApp` allow a single Shipit instance to serve **multiple GitHub organizations**, each with its own `webhook_secret` configured under `secrets.github[<org>]` [1](#0-0) . Any org admin who onboards their org into this Shipit instance necessarily knows their own org's webhook secret, since they choose it themselves when creating the GitHub App (`docs/setup.md`: "Webhook secret … Fill it with some randomly generated string" [2](#0-1) ). `WebhooksController#verify_signature` selects *which* org's secret to HMAC-verify against using a field taken straight from the untrusted, attacker-supplied JSON body — `repository.owner.login` (or `organization.login`) — before any signature check has occurred [3](#0-2) [4](#0-3) . Once the HMAC check passes (using the attacker's own valid secret for their own org), the event handlers resolve the target `Repository`/`Stack` using a **different** field of the same body, `repository.full_name` [5](#0-4) , with no cross-check that `full_name`'s owner segment matches the org whose secret authenticated the request.

### Finding Description
The trust binding that should hold is:
`organization whose secret authenticated the webhook == organization that owns the repository the handler mutates`

Before the attacker's request: an attacker only controls Org A (their own tenant, onboarded into the shared Shipit instance) and possesses Org A's `webhook_secret`. They have no access to Org B's repos, Stacks, or secrets.

After the attacker's request: by directly POSTing to `/webhooks` with a hand-crafted JSON body where `repository.owner.login = "OrgA"` (so `verify_signature` picks Org A's `GitHubApp` and its HMAC succeeds) but `repository.full_name = "OrgB/victim-repo"`, the request passes signature verification, and downstream handlers act on Org B's Stack/commits because `Handler#repository_name` and per-handler `repository` lookups use `full_name`, not `repository.owner.login` [6](#0-5) [7](#0-6) .

Because the HMAC is computed over the entire raw POST body, the signature *is* technically valid for the body sent — but the body's internal consistency (owner vs. full_name) is never checked. The signature only proves "this body was signed with Org A's secret," not "this body only references Org A's repositories." This is the same class of bug as the reported one: a field that gets *acted upon* (`repository.full_name`) is not the field the authorization/verification decision is actually *bound to* (`repository.owner.login`).

The `StatusHandler` is the most damaging target: it looks up commits purely by SHA (globally, across all stacks) and creates a `Status` from attacker-controlled `state`/`context`/`description`, with no repository-ownership check at all [8](#0-7) . A forged `success` status can flip a victim commit's state and trigger continuous deployment / merge-request processing [9](#0-8) , and `ContinuousDeliveryJob`/`ProcessMergeRequestsJob` can result in an actual unauthorized deploy on the victim stack (as demonstrated by `test/models/commits_test.rb` showing that a `success` status with continuous_deployment enabled triggers a `Deploy` [10](#0-9) ).

### Impact Explanation
This crosses the "unauthorized deploy" / "cross-repository writes" bar explicitly listed as Critical impact for this scan: an attacker who only administers their own onboarded organization (and thus its webhook secret) can forge CI status/check events, push-sync triggers, and PR/review-stack lifecycle events for a completely different organization's repository tracked by the same Shipit instance, without ever compromising that organization's credentials. In the `StatusHandler` case, this directly enables triggering an unauthorized deploy of a victim's stack (via continuous deployment) by forging a passing status on the head commit.

### Likelihood Explanation
The likelihood is directly tied to a real deployment shape supported by the code (`Shipit.github_organizations`, `github_app_config` keyed by org) — multi-tenant Shipit installations are an explicitly supported configuration, not a hypothetical. Any onboarded organization admin (a low-privilege actor relative to the Shipit instance as a whole and to other tenants' repos) already possesses the exact secret needed to mount this attack, and the request itself is a single crafted HTTP POST to a public, unauthenticated `/webhooks` endpoint (`skip_before_action :verify_authenticity_token`, no session or app-level ACL) [11](#0-10) .

### Recommendation
After `verify_signature` succeeds, re-derive/validate that the organization segment of `repository.full_name` (and of `organization.login` where relevant) matches the `repository_owner` value that was used to select the verifying secret, and reject the request (422) on mismatch. Equivalently, resolve the `Repository`/`Stack` scoped to the authenticated organization rather than trusting `full_name` in isolation inside `Handler#repository_name` and each handler's `repository` lookup.

### Proof of Concept
1. Configure Shipit for two tenants, e.g. `secrets.github["orga"]` and `secrets.github["orgb"]`, each with its own `webhook_secret` (as documented in `docs/setup.md`) [12](#0-11) .
2. As the (unprivileged, relative to OrgB) admin/owner of OrgA, who knows OrgA's `webhook_secret`, build a JSON body:
```json
{
  "sha": "<victim-commit-sha-in-orgb-stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "orga" }, "full_name": "orga/victim-doesnt-matter" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(orgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "orga")` (from `repository.owner.login`) and the HMAC checks out against OrgA's secret [3](#0-2) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` globally (not scoped by the verified org) and creates a `success` status for the victim commit belonging to OrgB's stack [8](#0-7) , potentially firing OrgB's continuous deployment.

**Caveat:** I could not fully verify within the available index whether every multi-tenant Shipit deployment enforces stack-to-organization scoping elsewhere (e.g., at the `Repository`/`Stack` model level) that might mitigate this in practice; the `Handler`, `PushHandler`, `StatusHandler`, and PR handlers reviewed all resolve targets purely from payload fields (`full_name` or global `sha` lookup) with no organization cross-check. If such scoping exists elsewhere and isn't visible in this index, it would need to be confirmed via a full repository clone (Devin session) before treating this as fully unmitigated.

### Citations

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L100-105)
```markdown
    oauth:
      id: Iv1.bf2c2c45b449bfd9
      secret: ef694cd6e45223075d78d138ef014049052665f1
      teams:
    domain: # The domain name of your GitHub Enterprise instance, leave it empty if you use github.com
```
```

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
