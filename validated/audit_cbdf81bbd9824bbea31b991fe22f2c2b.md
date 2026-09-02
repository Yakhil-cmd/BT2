### Title
Unscoped commit-SHA lookup in `status` webhook lets one authenticated organization forge deploy-triggering statuses on another organization's commits - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/secret belonging to a single organization derived from the payload (`repository_owner`), then dispatches the payload to the matching event handler. For the `status` event, `StatusHandler#process` looks up the target `Commit` **globally by SHA only**, with no scoping to the repository/organization that was actually authenticated. This breaks the equality that should hold: "the organization whose signature authenticated the request" == "the repository/stack whose data is written." Any organization legitimately onboarded to this Shipit instance can therefore push a validly-signed `status` webhook whose `sha` happens to match a commit tracked under a *different* organization's stack, and have Shipit apply that status (state/description/target_url/context) to the foreign commit.

### Finding Description
Signature verification is organization-scoped: `Shipit.github(organization: repository_owner)` selects the webhook secret for the org named in the payload, and `verify_webhook_signature` HMACs the whole raw body against that org's secret. [1](#0-0) 

Most handlers correctly scope their side effects through `Handler#stacks`, which filters by `Repository.from_github_repo_name(repository_name)` (i.e., by the `repository.full_name` in the very same authenticated payload): [2](#0-1) 

`StatusHandler`, however, does not use this repository scoping at all — it resolves the target commit purely by SHA across the entire application: [3](#0-2) 

This means the binding actually enforced is "organization X's secret signed this payload," while the binding acted upon is "any commit in the database whose SHA equals `params.sha`" — regardless of which repository/organization that commit belongs to. Since git commits are frequently shared across repositories (forks, mirrors, shared upstream history, vendored merges, cherry-picked/rebase-preserved commits), an attacker who legitimately controls one onboarded organization's GitHub repository (and thus can produce validly-signed `status` webhooks for that org) can craft/trigger a status update whose `sha` matches a commit that also exists in a victim organization's tracked stack, causing Shipit to record a fabricated CI/status entry (e.g., `state: "success"`) on the victim's commit via `Commit#create_status_from_github!`.

### Impact Explanation
A forged "success" status on a commit can drive `Stack` continuous-deployment logic (status transitions feed `add_status`/`deployable_status` hooks and CD triggers observed in `app/models/shipit/commit.rb` and referenced continuous-delivery job tests), meaning an attacker who only controls one tenant/org's repository in a multi-org Shipit deployment can influence whether another organization's commit is considered deployable/green, potentially triggering or unblocking an unauthorized deploy. This crosses the "organization authenticated vs. repository written" trust boundary called out for this bug class, and can result in an unauthorized deploy — a Critical-tier impact per the engine's threat model.

### Likelihood Explanation
Requires only that the attacker control (or have push/webhook-trigger rights on) one GitHub organization/repository that is already legitimately onboarded to the same multi-tenant Shipit instance — no Shipit credentials, API tokens, or privileged Shipit account are needed. The main constraint is finding/producing a SHA collision with a commit tracked in a different org's stack, which is realistic in fork/shared-history scenarios but not guaranteed for arbitrary targets, making this a real but conditional exploitation path.

### Recommendation
Scope `StatusHandler#process` the same way other handlers do: resolve the commit through `stacks` (i.e., filter by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) before matching on SHA, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent join that requires both the authenticated repository and the SHA to match, rather than matching SHA alone across the whole instance.

### Proof of Concept
1. Onboard two organizations, `org-A` and `org-B`, to the same Shipit instance, each with its own GitHub App/webhook secret.
2. Ensure (or arrange, e.g., via a fork/shared base commit) that a commit with SHA `S` exists both in a repository under `org-B` (tracked by a Shipit stack) and in a repository under `org-A` that the attacker controls.
3. Attacker triggers/crafts a `status` GitHub webhook event from `org-A`'s repository for commit `S` with `state: "success"`.
4. GitHub (or the attacker's own delivery, correctly HMAC-signed with `org-A`'s webhook secret) POSTs to `WebhooksController#create`; `verify_signature` succeeds because the signature is valid for `org-A`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` [3](#0-2)  — with no repository filter — and finds/updates the commit belonging to `org-B`'s stack, recording an attacker-controlled "success" status on it, potentially triggering continuous deployment for `org-B`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
