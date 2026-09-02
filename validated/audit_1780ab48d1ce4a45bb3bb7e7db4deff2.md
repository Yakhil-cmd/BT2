### Title
Webhook signature only authenticates the signing organization, not the repository/commit the payload acts on, enabling cross-repository status forgery and unauthorized merges - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC against using an untrusted field of the incoming payload (`repository.owner.login` / `organization.login`), and only proves that *some* onboarded organization's secret was used to sign the raw body. It does not verify that the repository, stack, or commit that the payload subsequently acts on (`repository.full_name`, or in `StatusHandler`, a bare `sha`) actually belongs to that organization. Any organization legitimately onboarded to a shared Shipit instance can therefore forge a webhook body whose `repository`/`sha` fields point at a stack owned by a different organization, and the request will pass signature verification and be processed against the victim's data.

### Finding Description
`verify_signature` computes the signing key from the payload before the payload is trusted: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` picks a `GitHubApp` config purely by that string, and `verify_webhook_signature` checks the HMAC of the *entire raw body* against that organization's `webhook_secret`: [3](#0-2) 

Nothing ties `repository.owner.login` (used to pick the secret) to the *other* fields in the same body that handlers use to select which data to mutate. In particular:

- `Handler#repository_name`/`#stacks` resolve the target repository purely from `repository.full_name`, a sibling field to `repository.owner.login` inside the same JSON object, with no re-validation that it is consistent with the signing organization: [4](#0-3) 

- `StatusHandler#process` is even less scoped: it looks up commits **globally by `sha`**, independent of stack, repository, or the signing organization at all, and writes a GitHub status onto whatever commit matches: [5](#0-4) 

Because the attacker crafts the raw JSON body themselves (it is not a real GitHub-originated payload with internally consistent `owner`/`full_name`), they can sign a body with their own organization's legitimately-known webhook secret while setting `repository.full_name`/`sha` to point at a different, unrelated stack/commit tracked by the same Shipit instance. The HMAC still validates because it covers the exact bytes the attacker chose to sign, and `verify_signature` never re-derives the organization from the value it uses to authorize the action.

This mirrors the reported bug class: a field ("which organization is authenticated") is checked/bound, while a different field that the code subsequently *acts on* ("which repository/commit is written") is never covered by that same trust check — i.e., the binding `authenticated_organization == repository_written` is never enforced, exactly the "organization that authenticated versus the repository that is written" pattern.

### Impact Explanation
A commit's `Status` records (created via `StatusHandler`) feed directly into `MergeRequest::StatusChecker`/`all_status_checks_passed?`, which the merge queue uses to decide whether a PR is ready to be merged (`MergeRequest#merge!`): [6](#0-5) [7](#0-6) 

An attacker who administers any organization onboarded to the shared Shipit instance (with a webhook secret they legitimately know for their own org) can forge a `status` event with `state: "success"` for a commit sha belonging to a victim organization's stack. This falsely satisfies CI requirements and can cause an unauthorized merge to be executed on a repository the attacker has no access to — an "unauthorized merge" impact, which is explicitly listed as Critical severity.

### Likelihood Explanation
Requires the attacker to control (and have legitimately configured) at least one organization/app installation on the same multi-tenant Shipit instance — no cross-organization credential theft, no privileged Shipit account, and no write access to the victim's repository is needed, only knowledge of the attacker's own webhook secret. This is a realistic scenario for any shared/multi-org Shipit deployment.

### Recommendation
After verifying the HMAC, re-derive the repository/organization actually referenced by the payload (`repository.full_name`, or for `StatusHandler`, the stack that owns the matched commit) and reject the request (422) unless it matches the organization whose secret produced a valid signature. Additionally, scope `StatusHandler#process` (and any other handler) to the repository resolved via `stacks`, not to a global `Commit.where(sha:)` lookup.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, which is configured in this Shipit instance with `webhook_secret = S` (their own, self-configured secret).
2. Victim stack `victim-org/victim-repo` has an open merge-queued PR whose head commit sha is `deadbeef...` (observable via GitHub's public API/UI) and is missing/failing required status checks.
3. Attacker builds a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "deadbeef...",
  "state": "success",
  "context": "required-ci-check"
}
```
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC(S, body)` using their own known secret `S`.
5. POST to `/github/webhooks` with header `X-Github-Event: status`.
6. `verify_signature` picks `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and validates the HMAC against `S` — it passes, since the attacker signed with their own key.
7. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, globally matches the victim's commit (independent of `attacker-org`), and creates a `success` `Status` on it.
8. The merge queue for `victim-org/victim-repo` now considers the required status satisfied, potentially triggering `MergeRequest#merge!` and an unauthorized merge to the victim's repository.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
