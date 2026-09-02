### Title
Cross-organization CI status forgery via unscoped commit lookup — organization that authenticated a webhook is never bound to the commit it mutates ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub `status` webhook against the secret of a *single* organization (derived from `repository.owner.login` in the payload), but the handler that actually processes the event — `StatusHandler#process` — looks up the target `Commit` purely by SHA, with no scoping back to the organization/repository whose secret validated the request. This breaks the binding `organization that signed the webhook == repository/commit that gets mutated`, letting a legitimately-authenticated org (or a payload accepted under a differently-configured org) overwrite CI status on commits belonging to any other stack/organization tracked by the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate against using attacker-supplied JSON fields, before the signature has even been checked: [1](#0-0) [2](#0-1) 

The signature only proves that *some* organization configured in Shipit produced this exact byte-for-byte payload — it never proves the payload's content ("this commit," "this repository") actually belongs to that organization's namespace. That correspondence must be enforced by the handler.

For `status` events, `StatusHandler` does not enforce it at all: [3](#0-2) 

`Commit.where(sha: params.sha)` is a global lookup with no `stack_id`/`repository_id`/organization filter, unlike the base `Handler#stacks` helper used by other handlers (e.g. `PushHandler`) which scopes through `Repository.from_github_repo_name(repository_name)`: [4](#0-3) [5](#0-4) 

Because git commit SHA1 hashes are a pure function of commit content (tree, parents, author/committer, timestamp, message) and are not secrets, an attacker who controls (or creates) their own GitHub organization/repository with the Shipit GitHub App installed can:
1. Reconstruct byte-identical commit objects (same SHA) as commits tracked by a *different* organization's Shipit stack (e.g., by re-creating the exact tree/parent/author/committer/message/timestamp of an existing public commit).
2. Push that commit into their own repository and set a commit status (`success`) on it via the GitHub API for their own repo — this is a completely normal, unprivileged action on a repository they own.
3. GitHub fires a genuine, correctly-signed `status` webhook to Shipit, using the attacker's own organization's real `webhook_secret`.
4. `WebhooksController#verify_signature` validates the signature using the attacker org's own secret — legitimately, since the payload really was produced and signed for that org.
5. `StatusHandler#process` then updates `Commit.create_status_from_github!` for **every** `Commit` row across the entire Shipit installation whose SHA matches, regardless of which repository/organization actually owns it — including a target commit belonging to a completely unrelated organization/stack.

This is exactly the "organization that authenticated versus the repository that is written" binding called out as the deployment-trust boundary: the identity verified by `verify_webhook_signature` is never carried through to the object mutated by the handler.

### Impact Explanation
Shipit stacks gate merges/deploys on commit CI status (`ignore_ci`, merge-queue status checks). Forging a `success` status on an arbitrary commit SHA tracked by another organization's stack lets an attacker who controls only their own, unrelated GitHub organization mark a target organization's pending/blocking commit as passing CI. Combined with Shipit's merge queue and deploy pipelines that rely on stored commit `Status` rows to decide whether a commit is safe to merge/deploy, this can result in an unauthorized deploy or an unauthorized merge of a commit that never actually passed the target repository's real CI — landing in the "Critical: unauthorized deploy, rollback or merge" bucket. The attack requires no session, no `ApiClient` token, no knowledge of the target's `webhook_secret`, and no write access to the target's repository — only ordinary control of the attacker's own, separately-onboarded GitHub organization/repository.

### Likelihood Explanation
Reproducing an identical SHA requires reconstructing exact commit object bytes, which is only practical when the target commit's full commit metadata is already known/public (e.g. mirrored open-source commits, or commits visible via other Shipit-exposed UI/API surfaces that leak SHA + metadata). This constrains the attack to specific known-commit scenarios rather than being universally trivial, but the underlying code defect — a completely unscoped `Commit.where(sha:)` lookup reachable by any webhook-authenticated organization — is a straightforward, deterministic bug with no additional mitigations in the code path.

### Recommendation
Scope `StatusHandler#process` (and any other handler using bare identifier lookups) to the repository/organization that was actually verified by `verify_webhook_signature`, mirroring what `Handler#stacks`/`Repository.from_github_repo_name` already do for push events, e.g.:
```ruby
def process
  Commit.joins(stack: :repository)
        .where(sha: params.sha, shipit_repositories: { full_name: repository_full_name })
        .each { |commit| commit.create_status_from_github!(params) }
end
```
where `repository_full_name` is derived from the same payload used during signature verification, ensuring the authenticated organization can only mutate commits belonging to its own repositories.

### Proof of Concept
1. Attacker creates GitHub organization `attacker-org` and installs the Shipit GitHub App on it (own, unprivileged action — no access to the victim organization needed).
2. Attacker identifies a commit tracked by a victim stack, e.g. SHA `abc123...` in `victim-org/victim-repo`, with fully known commit metadata (tree hash, parent, author, committer, timestamp, message) — obtainable from any public mirror or from Shipit's own commit views.
3. Attacker crafts an identical git commit object (same content ⇒ same SHA1) inside `attacker-org/attacker-repo` and pushes it.
4. Attacker calls the GitHub Status API on their own repo/commit: `POST /repos/attacker-org/attacker-repo/statuses/abc123... {"state":"success", ...}`.
5. GitHub sends Shipit a `status` webhook, correctly signed with `attacker-org`'s own `webhook_secret`.
6. `WebhooksController#verify_signature` passes (real signature, real org).
7. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, matches the victim's commit row (owned by `victim-org/victim-repo`), and marks it `success` — even though `attacker-org` never had any relationship with `victim-org`'s repository. [3](#0-2) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
