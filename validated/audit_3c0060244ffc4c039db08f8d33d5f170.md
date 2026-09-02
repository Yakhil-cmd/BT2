### Title
Cross-organization webhook forgery via mismatched authentication key vs. acted-upon repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret to validate an inbound webhook's HMAC signature using `repository.owner.login` (falling back to `organization.login`), but the handlers that actually act on the payload (creating jobs, syncing commits, writing statuses, opening/closing review stacks) key off a *different* field — `repository.full_name` — to look up the `Shipit::Repository`/`Stack` to operate on. Nothing ties these two fields together, so a signature that is valid for org A's webhook secret does not guarantee the payload's `repository.full_name` actually belongs to org A.

### Finding Description
`verify_signature` computes the verifying key like this: [1](#0-0) 
and [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` and is used purely to pick *which org's* `webhook_secret` in `Shipit.github(organization: ...)` should validate `X-Hub-Signature` over `request.raw_post`.

Once the signature check passes, every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s) resolves the target repository independently via `Shipit::Webhooks::Handlers::Handler#repository_name`, which reads a completely different JSON key: [3](#0-2) 

and `PushHandler#process` immediately syncs a `Stack` matching that repository's branch: [4](#0-3) 

All the `PullRequest::*` handlers do the same, resolving `Shipit::Repository.from_github_repo_name(params.repository.full_name)` independent of `repository.owner.login`: [5](#0-4) 

This is the same class of bug as the reported Story Protocol issue: a field that the verification step commits to (`repository.owner.login`, used to select the HMAC key) is not the same field the business logic subsequently trusts and acts upon (`repository.full_name`, used to select which repository/stack is written to). The equality that should hold — "the organization whose secret validated this payload" == "the organization that owns the repository being acted on" — is never checked. Since HMAC-SHA1 signature verification only proves *a* value known to the signer produced this exact byte string, not that the embedded `repository.full_name` is consistent with `repository.owner.login`, anyone who legitimately knows *any* configured organization's `webhook_secret` (e.g., an org admin who set up their own org's GitHub App/webhook integration into a shared, multi-tenant Shipit instance — a normal, unprivileged-with-respect-to-other-orgs scenario) can freely forge `repository.full_name` to point at a stack belonging to a different, unrelated organization/repository that they have no access to.

### Impact Explanation
An attacker who controls (or is an admin of) one organization configured in a multi-tenant Shipit deployment can sign arbitrary JSON payloads with their own org's `webhook_secret` while setting `repository.full_name` to a victim organization's repository. This lets them:
- Trigger `GithubSyncJob` for a foreign stack (`PushHandler`), forcing Shipit to sync from the real upstream and cache a deploy spec derived from a `expected_head_sha` of the attacker's choosing.
- Forge `status`/`check_suite` events for arbitrary commits in a foreign repository (via `StatusHandler`/`CheckSuiteHandler`), fabricating passing CI results Shipit trusts for gating deploys and for `MergeRequest#all_status_checks_passed?` in the merge queue.
- Open/close/label review stacks for a foreign repository's pull requests, provisioning or archiving infrastructure not belonging to the attacker's org.

Fabricating CI status directly undermines Shipit's `merge_request_required_statuses`/`blocking_statuses` gating (`MergeRequest#reject_unless_mergeable!`, `StatusChecker`), which can enable an unauthorized merge/deploy of a stack the attacker does not have GitHub write access to — matching the Critical "unauthorized deploy, rollback or merge" impact bucket, via a cross-repository write path with no session, `ApiClient` token, or GitHub write access required on the victim repo.

### Likelihood Explanation
Requires only knowledge of a `webhook_secret` for *some* org configured on the shared Shipit instance (something the attacker can obtain legitimately if they administer their own org's GitHub App/webhook config pointing at that shared instance) plus the ability to craft an arbitrary JSON body and compute a SHA1 HMAC — both achievable without any interaction with the victim organization or repository. This is realistic for any Shipit deployment serving more than one GitHub organization from the same `Shipit.github(organization:)` multi-config, which the codebase explicitly supports (`repository_owner` fallback logic, `test/dummy/config/secrets_double_github_app.yml`).

### Recommendation
Cross-validate that the organization used to select the signing/verification secret matches the owner organization of `repository.full_name` (and of `organization.login` for org-level events) before dispatching to any handler — i.e., derive both from the same trusted field, or explicitly assert `repository.full_name.split('/').first == repository_owner` (case-insensitively) in `WebhooksController#verify_signature`, rejecting the request with 422 on mismatch.

### Proof of Concept
1. Attacker is an admin of GitHub org `attacker-org`, which has a Shipit-integrated GitHub App with known `webhook_secret_A` on a shared multi-tenant Shipit instance that also serves `victim-org/victim-repo`.
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(webhook_secret_A, body)` and POSTs to `/shipit/webhooks`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verifies successfully against `webhook_secret_A`.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, and enqueues `GithubSyncJob` for the victim's stack — despite the attacker having no relationship to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
