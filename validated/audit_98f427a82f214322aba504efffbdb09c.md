### Title
Cross-organization commit status forgery breaks the "organization that authenticated" vs "repository that is written" binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit supports multi-organization configurations where each GitHub organization has its own App/installation and webhook secret [1](#0-0) . The webhook signature is verified against the secret belonging to `repository.owner.login` from the payload [2](#0-1) , so a request is only proven to originate from the organization named in that same payload. However, `StatusHandler#process` never re-checks that the commit being updated actually belongs to a repository owned by that authenticated organization — it looks the commit up globally by `sha` alone.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `repository_owner`, derived from the payload's `repository.owner.login` (or `organization.login`) [3](#0-2) . This authenticates "organization X sent this webhook", not "organization X is authorized to write to repository Y". Every other handler that mutates state re-derives the target through `Repository.from_github_repo_name(repository_name)` before touching any records, e.g. `Handler#stacks` [4](#0-3)  and `PushHandler#process`, which explicitly scopes to `stacks` derived from that repository [5](#0-4) .

`StatusHandler`, by contrast, ignores the `repository` field entirely and updates commits purely by SHA, with no scoping to the authenticated organization's repository/stacks: [6](#0-5) 

This breaks the binding: `organization authenticated by signature == repository/commit actually written`. Any organization configured in Shipit (with a legitimate, valid installation and webhook secret for its own repos) can send a `status` event referencing an arbitrary commit `sha`. If that SHA happens to also exist as a commit in a *different* organization's/repository's stack tracked by the same Shipit instance (e.g., shared history from a fork, monorepo split, cherry-picked/rebased commit, or a low-entropy short-sha collision path if ever accepted), the status is applied to that foreign commit via `Commit#create_status_from_github!`, regardless of which org actually owns that repository.

### Impact Explanation
Commit statuses feed directly into `deployable?` checks used to gate deploys/merges for a stack. A status forged this way could mark a commit in another organization's stack as passing CI when it did not, or as failing when it did, enabling an **unauthorized deploy** decision to be manipulated on a repository the requesting organization does not own. This crosses the "authenticated org vs. repository being written" boundary called out explicitly in scope, and the practical effect (an unauthorized/undeserved deploy gate bypass) matches the "High" impact bucket (unauthorized deploy) defined for this analysis.

### Likelihood Explanation
Exploitability depends entirely on Shipit being configured for multiple GitHub organizations sharing one instance (supported via `github_app_config`/`github_organizations` [7](#0-6) ) and on a SHA collision/overlap occurring between repositories tracked under different organizations. This is a real but narrower precondition than a single-tenant deployment, and I could not verify from the available code whether any additional uniqueness constraint (e.g., DB index scoping `Commit` uniqueness by `stack_id`+`sha` only, not globally) would prevent identical SHAs from being legitimately associated with unrelated stacks — this appears likely given `Commit.where(sha: params.sha)` is written to match across all stacks without any additional filter. Because of index size limits I was not able to fully inspect `app/models/shipit/commit.rb`'s status-creation logic and its downstream effect on `deployable?`/CI gating in complete detail; a Devin session with full repository access would let a reviewer verify the exact downstream consequence chain.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by content rather than by the authenticated repository) to only update commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')`, mirroring the pattern already used in `Handler#stacks`/`PushHandler`. E.g., restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` or add an explicit repository/stack join condition before calling `create_status_from_github!`.

### Proof of Concept
Conceptual (not executed, since this requires a live multi-org Shipit deployment and a genuine SHA collision, which I could not fabricate or verify from source alone):
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own GitHub App and webhook secret, per `github_app_config` [8](#0-7) .
2. `org-a` legitimately controls a repo containing commit `SHA1` (e.g., via a shared fork/rebase history that also exists in `org-b`'s tracked repo).
3. `org-a`'s installation sends a valid, correctly-signed `status` webhook referencing `SHA1` with `state: success`.
4. `WebhooksController#verify_signature` validates the signature using `org-a`'s webhook secret and passes.
5. `StatusHandler#process` runs `Commit.where(sha: SHA1)` globally and creates a passing status on the commit as it exists in `org-b`'s stack, even though `org-a` was never authenticated to act on `org-b`'s repository.

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
