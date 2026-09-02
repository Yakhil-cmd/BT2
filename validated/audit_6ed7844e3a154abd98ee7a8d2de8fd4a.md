### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit binds webhook-signature verification to the organization named in the payload's `repository.owner.login` field, but `StatusHandler` — unlike every other webhook handler — never re-checks that the commit it mutates actually belongs to the repository that was authenticated. This breaks the intended equality: *{organization/repository whose secret verified the request} == {repository whose data is written}*.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization config to validate the HMAC signature using `repository_owner`, derived from the payload itself: [1](#0-0) [2](#0-1) 

Every other handler scopes its writes through `Handler#stacks`, which resolves the target `Repository` from `payload.dig('repository', 'full_name')` before touching any records: [3](#0-2) 

`StatusHandler`, however, ignores `repository_name`/`stacks` entirely and looks up commits **globally by SHA alone**, across every repository and organization configured in the Shipit instance: [4](#0-3) 

Since a `status` webhook's signature only proves that *some* org/repo the requester controls emitted it (verified against that org's `webhook_secret`), and the handler never checks `params.dig('repository', 'full_name')` against the commit's actual stack/repository, a correctly signed status event from a low-trust repository can update the CI status of a commit belonging to a completely different, unrelated repository/organization, as long as the SHA values collide.

Git commit SHA-1 hashes are pure functions of commit content (tree hash, parent hash(es), author/committer identity and timestamps, message) — not of which repository stores them. An attacker with ordinary push access to any repository already onboarded to the same Shipit instance can reconstruct a commit object byte-for-byte identical to a target commit in a higher-trust repository (its tree/parent hashes and metadata are derivable from that repository's own git history, which is typically readable), push it into their own repo, and then trigger a `status` webhook on their own repo with that SHA. The webhook is legitimately signed by their own organization's `webhook_secret`, passes `verify_signature`, and `StatusHandler` applies it to every `Shipit::Commit` row sharing that SHA — including the one in the victim repository/organization.

### Impact Explanation
CI/commit statuses gate deployability and mergeability in Shipit (`ci.require` in `shipit.yml`, continuous-delivery gating). Forging a "success" status on a commit in a repository/organization the attacker does not control can make that commit appear deployable/mergeable, enabling an unauthorized deploy or merge — matching the Critical impact class of "cross-repository writes, or an unauthorized deploy, rollback or merge." This requires no privileged Shipit account, `ApiClient` token, or the target's webhook secret — only ordinary push/webhook-triggering rights on any other repository already configured in the same multi-tenant Shipit deployment.

### Likelihood Explanation
The prerequisite (onboarding of multiple, independently-trusted repositories/organizations to one Shipit instance, and the ability to craft/replay an identical-SHA commit) is realistic for shared internal Shipit deployments serving many teams/orgs, and constructing colliding commit content (matching tree, parents, author/committer timestamps, and message) is a known, low-effort technique — no cryptographic break is required, only careful metadata replication.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup to the repository named in the payload (via `stacks`, mirroring every other handler), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, rather than an unscoped `Commit.where(sha: params.sha)` across the whole instance.

### Proof of Concept
1. Shipit instance has two onboarded repositories: `victim-org/high-trust-repo` (org A) and `attacker-org/low-trust-repo` (org B), each with its own GitHub App `webhook_secret`.
2. Attacker has ordinary push access to `attacker-org/low-trust-repo` and knows (from public git history) the exact tree/parent/author/committer/message/timestamp of a commit `C` currently tracked as a `Shipit::Commit` in `high-trust-repo`'s stack.
3. Attacker reconstructs commit `C` byte-for-byte in `low-trust-repo`, producing an identical SHA-1, and pushes it (or otherwise causes a `status` event referencing that SHA to be emitted, e.g. via GitHub's Statuses API on their own repo).
4. GitHub sends the `status` webhook to Shipit, HMAC-signed with org B's `webhook_secret`. `WebhooksController#verify_signature` looks up org B via `repository.owner.login` and successfully verifies it.
5. `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the `Shipit::Commit` row belonging to `high-trust-repo` (org A), and calls `commit.create_status_from_github!(params)`, writing the attacker-chosen `state`/`context`/`description` onto that commit — even though the request was authenticated only for org B/`low-trust-repo`.

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
