### Title
Cross-repository commit-status forgery via unscoped `StatusHandler#process` breaks the "authenticated repository = repository written" binding — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` only proves that the incoming webhook was HMAC-signed with the secret of *some* configured GitHub App/organization — the one identified by the untrusted, attacker-influenced JSON field `repository.owner.login` (or `organization.login`): [1](#0-0) [2](#0-1) 

Every other webhook handler in the engine then re-derives *which repository/stack* the event applies to from `repository.full_name` via the shared `Handler#stacks`/`repository_name` helper, so the entity that authenticated and the entity being mutated are the same repository: [3](#0-2) 

`StatusHandler`, however, breaks this binding: it never scopes its lookup by repository at all. It resolves the target `Commit` purely by SHA, globally, across every stack/repository tracked by the whole Shipit installation: [4](#0-3) 

This is exactly the class of bug in the external report: the code verifies a *caller* (the connector/organisation) is a trusted, authenticated party, but the object actually acted upon (`destinationConnector`/`Commit`) is never checked to belong to that same trusted party. Here the equality that should hold — `organization that authenticated == repository whose commit is written` — is never enforced; the only enforced equality is `organization that authenticated == organization named in one payload field`, which is unrelated to which `Commit` row ends up mutated.

Git commit SHAs are content-addressed and are frequently identical across a fork and its upstream (or across mirrored/rebased/cherry-picked repositories), so any attacker who can generate a legitimately GitHub-signed `status` webhook for *some* repository they control (their own public fork, or any repository whose GitHub App/webhook secret they legitimately have, however unprivileged relative to the victim) can post a commit status that matches a SHA that also exists as a `Commit` in a completely unrelated Stack belonging to a different, victim repository/organization tracked by the same Shipit instance.

### Impact Explanation
`Commit#create_status_from_github!` writes a `Status` (e.g. state `success`) attached to the resolved `Commit`. Because `Commit.deployable?` and continuous-delivery scheduling in `Stack` depend on the aggregated status state of a commit, an attacker can inject a fabricated "green CI" status onto a real commit belonging to a victim stack they have no access to, without ever needing that victim stack's webhook secret, an `ApiClient` token, or a Shipit session — only the ability to produce one legitimately-signed status webhook for an unrelated, attacker-reachable repository whose commit SHA collides with (or was deliberately reused/cherry-picked to match) a commit in the victim stack. On stacks with `continuous_deployment` enabled or where CI status gates manual deploys, this can result in an unauthorized deploy of a commit that never actually passed the victim's CI — matching the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Exploitation requires: (1) a Shipit instance tracking at least two independent repositories/stacks (the common multi-tenant deployment described in `docs/setup.md`'s "Using Multiple Github Applications" section), and (2) the attacker's ability to cause a genuinely GitHub-signed `status` event for a repository they control (e.g., their own fork, where they can post commit statuses via the GitHub API) whose commit SHA also appears in the victim stack's commit history. Achieving a matching SHA is realistic in fork/cherry-pick/rebase-preserving workflows, which are common in open-source and monorepo-mirroring setups, but it is not guaranteed for arbitrary target commits, so likelihood is moderate rather than trivial.

### Recommendation
Scope `StatusHandler#process` to the repository named in the webhook payload, consistent with every other handler, e.g. restrict the commit lookup to `stacks.map(&:commits)` (or a `Commit.joins(:stack).where(stack: stacks, sha: params.sha)`) so a status can only be applied to commits belonging to the authenticated repository's own stacks, closing the gap between "organization that authenticated" and "commit that gets written."

### Proof of Concept
1. Deploy Shipit tracking two repositories in two different GitHub orgs/apps: `victim-org/app` (Stack B, `continuous_deployment: true`) and `attacker-org/fork` (any repo the attacker can push to and has a configured, or even independently-installed, GitHub App/webhook for).
2. Attacker crafts a commit in `attacker-org/fork` whose SHA is identical to a real commit `C` already present in Stack B's history (e.g., by cherry-picking/rebasing a public commit from `victim-org/app` into their own fork, preserving the SHA — trivial with `git cherry-pick` since content+parents+committer info determine the SHA, and forks frequently share ancestor commits).
3. Attacker uses the GitHub Statuses API (`POST /repos/attacker-org/fork/statuses/{sha}`) to set `state: success` on that SHA. GitHub delivers a legitimately-signed `status` webhook to Shipit for `attacker-org/fork`.
4. `WebhooksController#verify_signature` succeeds because the signature validly matches `attacker-org`'s own webhook secret — [1](#0-0) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` with no repository filter — [4](#0-3)  — and finds commit `C` belonging to Stack B, attaching the forged `success` status to it.
6. If Stack B's continuous-delivery logic considers `C` deployable based on this forged status, an automatic (unauthorized) deploy of `C` is triggered on `victim-org/app`, even though the attacker never had write access to `victim-org/app` and never touched its real CI or webhook secret.

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
