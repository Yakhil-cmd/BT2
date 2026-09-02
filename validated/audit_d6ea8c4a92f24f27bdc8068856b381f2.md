### Title
Cross-repository CI status forgery via unscoped commit lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to update **only by SHA**, with no scoping to the repository/organization that the incoming webhook was authenticated for. This breaks the binding "organization that authenticated == repository whose commit is written": a webhook whose signature is validated against organization A's `webhook_secret` can cause CI status writes against a commit belonging to organization B's stack, as long as the two commits happen to share a SHA-1 value.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the signature with, using the organization derived from the payload itself: [1](#0-0) [2](#0-1) 

This only proves the request came from an app registered for *that* organization — it says nothing about which commits should be mutated. Every other event handler correctly re-derives the target scope from `repository.full_name` via the shared `Handler#stacks`/`Repository.from_github_repo_name` helper: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, never calls `stacks`/`repository_name` at all. It resolves the commits to mutate purely by SHA, globally across the entire `commits` table: [5](#0-4) 

Because `commit.create_status_from_github!(params)` is invoked for **every** row matching `sha`, any stack in the Shipit instance that happens to contain a commit with that same SHA gets its status updated too — regardless of which organization's webhook secret validated the request. This is exactly the class of bug described in the external report: a field ("PERMIT" in the external report; here, the `sha` used to select which record to mutate) is assumed to be scoped/ordered correctly by an earlier check, but the code path that actually acts on it does not enforce that assumption, so the check protecting the operation is effectively bypassed for anything other than the very first/obvious case.

Git commit SHA-1s are content-addressed (tree, parent, author/committer, timestamps, message), and an attacker who controls a repository can reconstruct a byte-identical commit object (e.g. by mirroring a public victim commit's tree and metadata) to produce an identical SHA that also exists in a victim's tracked repository/stack.

### Impact Explanation
An attacker who only controls their own repository (validly authenticated via their own org's `webhook_secret`, requiring no secret compromise) can forge a `status` webhook event whose `sha` collides with a commit tracked in a completely different organization's stack. Because `StatusHandler` updates all matching commits system-wide, the attacker can set an arbitrary `state`/`context`/`description`/`target_url` on the victim's commit. Since Shipit gates deploys on required CI statuses (`Stack#checks?`, `required_statuses`, `soft_failing_statuses`), forging a passing status for a required context can make an otherwise non-deployable commit appear deployable, leading to an **unauthorized deploy** of that commit in the victim's stack — a cross-repository write with Critical impact per the scope's own criteria.

### Likelihood Explanation
Exploitation requires: (1) the attacker owns/administers at least one repository/organization already integrated with the Shipit instance (a normal, unprivileged tenant of a multi-tenant Shipit deployment — no secrets need to be stolen), and (2) producing a commit whose SHA-1 collides with a target commit in a victim stack, which is feasible for public repositories by reproducing identical commit content/metadata. This is a realistic scenario in any multi-tenant Shipit install (the documented use case, since `Shipit.github` supports multiple organizations, e.g. `config/secrets.development.shopify.yml`).

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository the webhook was authenticated for, mirroring what `Handler#stacks`/`repository_name` already does for other handlers, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or otherwise join through `Repository.from_github_repo_name(repository_name)` before selecting `Commit` rows, so a status update can never cross repository/organization boundaries.

### Proof of Concept
1. Attacker controls `attacker-org/attacker-repo`, registered in Shipit with its own valid `webhook_secret`.
2. Attacker creates a commit in `attacker-repo` with tree/author/committer/timestamp/message identical to an existing commit `C` in `victim-org/victim-repo`'s Shipit-tracked stack, producing the same SHA-1.
3. Attacker triggers (or fabricates, since they know their own valid `webhook_secret`) a `status` event for `attacker-repo` with `sha = C`, `state = "success"`, `context = "<victim's required CI context>"`.
4. `WebhooksController#verify_signature` validates the signature using `attacker-org`'s `webhook_secret` successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which also matches commit `C` in `victim-repo`'s stack, and writes the forged status to it [5](#0-4) .
6. `victim-org`'s stack now shows a passing status for commit `C` for a context the attacker fully controls, potentially unblocking an unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
