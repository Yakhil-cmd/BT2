## Analysis

Confirmed root cause: `Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target `Commit` **globally**, without any scoping to the repository/organization whose GitHub App signature was verified.

Compare the two handlers:
- `PushHandler` and `CheckSuiteHandler` both start from `stacks` (defined in the base `Handler`), which is derived from `Repository.from_github_repo_name(repository_name)` — i.e. scoped to `payload.dig('repository', 'full_name')`. [1](#0-0) [2](#0-1) 
- `StatusHandler`, however, ignores `repository`/`stacks` entirely and queries `Commit.where(sha: params.sha)` across the **entire** `commits` table (all stacks, all repositories, all GitHub organizations configured in this Shipit instance), then writes a status onto whatever it finds: [3](#0-2) 

The binding that is verified is: `verify_signature` picks the GitHub App/secret using `repository_owner` extracted from the payload and HMAC-verifies the raw body against that organization's `webhook_secret`. [4](#0-3) 

The engine supports multiple GitHub organizations/Apps configured simultaneously (`Shipit.github(organization:)`, `github_organizations`), each with its own webhook secret. [5](#0-4) [6](#0-5) 

So the equality that should hold — "the organization/repository whose signature was verified == the stack/repository whose `Commit` state is mutated" — is broken for the `status` event: the signature only proves the payload came from a genuinely GitHub-signed webhook for *some* repository owned by *some* configured organization, but `StatusHandler` will happily flip the CI state of a `Commit` row belonging to a completely different stack/repository/organization, as long as the SHA1 matches (git commit hashes are content-derived and not secret — trivially reproducible by anyone who can create a commit with identical tree/parent/author/committer/message/timestamp, or who mirrors/forks the target repository and pushes the same commit).

Downstream, `Commit#deployable?` and `Stack#branch_status`/merge-queue logic rely directly on this status: [7](#0-6) [8](#0-7) 

An attacker who has legitimate (unprivileged w.r.t. the target) push/status access to *any* repository connected to *any* GitHub App configured in the same Shipit instance can fabricate a `status` webhook (via their own repo, which GitHub will sign correctly with their org's secret) whose `sha` matches a commit that also exists in a victim stack in a different repository/organization, flipping that victim commit's CI state to `success` and enabling an unauthorized deploy in the victim's stack.

### Title
Cross-repository/organization commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up target commits solely by SHA, with no repository or organization scoping, even though `Shipit::WebhooksController#verify_signature` authenticates the payload only against the GitHub App/secret of the organization named in the payload. Any commit sharing that SHA in *any* stack of *any* configured organization gets its CI status updated, breaking the "authenticated organization == repository written" binding.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#verify_signature` selects the verifying secret via `repository_owner` (derived from the payload) and HMAC-verifies the whole raw body against it. This only proves the request is a genuine webhook from *a* GitHub App installed on *some* org configured in `Shipit.github`. It does not, and cannot, restrict which `Commit`/`Stack` rows may subsequently be mutated — that restriction must be enforced by the handler.

`Handler#stacks` does enforce this correctly for other events by resolving `Repository.from_github_repo_name(payload.dig('repository','full_name'))` first. [1](#0-0) 

`StatusHandler#process`, however, bypasses `stacks`/`repository_name` completely: [3](#0-2) 

Because `Commit` rows for every stack in the Shipit instance live in a single `commits` table keyed by `sha` (see `Commit.by_sha`, `where('sha like ?', ...)`), and SHA1 hashes are public/derivable (not a secret), a `status` event legitimately signed for organization A's repository can update the status of a commit belonging to organization B's/another repository's stack, provided the SHA collides (trivial via forking/mirroring/cherry-picking the exact same commit into a different repository).

### Impact Explanation
This breaks the deploy-trust boundary "an organization that authenticated versus the repository that is written": an attacker with only write access to a repository under one configured GitHub App can influence CI state, hence deployability, of commits in a completely different stack/organization managed by the same Shipit instance. Since `Commit#deployable?` gates directly on status success/blocking, this can facilitate an unauthorized deploy or bypass required-status checks (`stack.required_statuses`, `blocking_statuses`) for a victim stack — matching the High/Critical impact bar ("escalation... unauthorized deploy...").

### Likelihood Explanation
Requires the instance to be configured for multiple GitHub organizations/Apps (an explicitly supported and documented configuration: `docs/setup.md`, `secrets_double_github_app.yml`), and requires the attacker to produce/control a commit with an identical SHA1 to the victim commit in a repository they can push/set-status on. This is feasible via forking or mirroring public/shared repositories, or in monorepo/multi-remote setups where the same commit is pushed to multiple remotes tracked by different Shipit stacks/orgs.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries `Commit`/`Stack` directly by content-derived identifiers) through `stacks`/`repository_name`, mirroring `PushHandler`/`CheckSuiteHandler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent, so a status update can only ever affect commits belonging to the repository named — and thus organization-verified — in the same signed payload.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with its own GitHub App/webhook secret (supported configuration, see `test/dummy/config/secrets_double_github_app.yml`).
2. Stack `OrgB/victim-repo` has an undeployed commit `C` with `sha = X` and a required CI status that is currently `pending`/`failure`.
3. Attacker (who only has push access to `OrgA/attacker-repo`, e.g. a fork/mirror of `victim-repo` containing the identical commit `C`, or any repo where they can reproduce SHA `X`) sets a commit status via the GitHub API for `OrgA/attacker-repo@X`.
4. GitHub sends a `status` webhook signed with `OrgA`'s `webhook_secret`. `WebhooksController#verify_signature` verifies it successfully against `OrgA`.
5. `StatusHandler#process` executes `Commit.where(sha: X)`, which matches the `Commit` row belonging to `OrgB/victim-repo`'s stack (a different, unrelated organization), and calls `create_status_from_github!`, flipping its CI state.
6. `victim-repo`'s stack now reports the commit as `deployable?` (or merge-queue eligible), even though the attacker had no access to `OrgB` or `victim-repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-21)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status/common.rb (L14-16)
```ruby
      def success?
        state == 'success'
      end
```
