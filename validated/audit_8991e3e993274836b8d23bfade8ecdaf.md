### Title
Cross-repository commit-status writes: verified webhook organization is never checked against the repository the `StatusHandler` writes to - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub App/organization derived from `repository.owner.login` (or `organization.login`) in the payload, but this authenticated organization/repository binding is discarded before the request reaches the handlers. `StatusHandler#process` resolves the target `Commit` purely by SHA, with no scoping to the repository that was actually verified, so a `status` webhook validly signed for one repository's organization can update commit status (and therefore release status / merge eligibility) for a `Commit` belonging to a completely different stack/repository whenever the SHA values match.

### Finding Description
The controller picks which `GithubApp` (and its `webhook_secret`) to use for signature verification based on the repository owner embedded in the payload: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the raw JSON `params` are dispatched unchanged to every matching handler: [3](#0-2) 

Most handlers correctly re-derive scope from `payload.dig('repository', 'full_name')` via the base `Handler#stacks` helper: [4](#0-3) 

However, `StatusHandler` (used for the GitHub `status` event) never calls `stacks`/`repository_name` at all. It looks up commits globally by SHA and mutates them: [5](#0-4) 

This breaks the trust binding: `organization authenticated by signature == repository whose Commit is written`. The signature only proves the payload was signed by *some* organization's configured `webhook_secret` for the `repository.owner.login`/`organization.login` present in the payload; it proves nothing about which `Commit` rows get updated, because `StatusHandler` matches by `sha` alone across all stacks/repositories in the Shipit instance.

### Impact Explanation
Any organization/repository already integrated with this Shipit instance (i.e., any tenant with its own configured GitHub App and `webhook_secret` for their own repository) can send a validly-signed `status` webhook event referencing a commit SHA that also exists in a different stack belonging to a different repository/organization (a highly plausible situation for forked/mirrored repositories, shared upstream history, or vendored commits). `Commit#create_status_from_github!` will then create a status for that unrelated `Commit`, which can flip `deployable_status`/`release_status`, unblock or block deploys, and influence `Stack#schedule_merges` for a repository the attacker has no legitimate relationship with — a cross-repository write achieved purely by controlling a different, legitimately-registered organization's webhook credentials rather than the target's.

### Likelihood Explanation
Exploitability requires only that the attacker administers any repository already onboarded to the same Shipit instance (their own webhook secret, which they legitimately possess), and that a commit SHA collision exists with the victim stack — realistic for forks, mirrors, cherry-picked/rebased shared history, or synced upstream branches, all common patterns in monorepo/fork-based engineering workflows that Shipit is designed to support (multiple stacks tracking related repositories). No privileged Shipit session, `ApiClient` token, or victim credentials are needed.

### Recommendation
`StatusHandler#process` (and any other handler that does not use `Handler#stacks`) must scope its `Commit` lookup to the repository verified during signature validation, e.g. by joining through `stack.repository` / `Repository.from_github_repo_name(repository_name)` as the base `Handler` class already does, rejecting or ignoring status updates for commits outside the authenticated repository's stacks.

### Proof of Concept
1. Attacker registers/administers `attacker-org/repo-a` as a Shipit stack, with its own GitHub App installation and `webhook_secret` (legitimately configured, no access to victim data required).
2. Attacker arranges (or already has, via fork/shared history) a commit with SHA `S` that is also present in `victim-org/repo-b`, a separate stack on the same Shipit instance.
3. Attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with `attacker-org`'s `webhook_secret`, and body `{"sha": "S", "state": "success", "repository": {"owner": {"login": "attacker-org"}}}`.
4. `WebhooksController#verify_signature` resolves and validates against `attacker-org`'s `GithubApp`, succeeds, then dispatches to `StatusHandler`.
5. `StatusHandler#process` executes `Commit.where(sha: "S").each { |c| c.create_status_from_github!(params) }`, which also matches and updates the `Commit` with SHA `S` in `victim-org/repo-b`, altering its deploy/release status without any relationship to `victim-org`. [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
