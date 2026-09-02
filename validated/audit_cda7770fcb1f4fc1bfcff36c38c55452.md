### Title
Webhook signature verification is bound to the wrong organization, allowing cross-repository status/commit-sync forgery in multi-tenant deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment (each org configured with its own GitHub App and `webhook_secret`, as documented in `docs/setup.md`), `WebhooksController#verify_signature` selects which secret to validate the incoming webhook's HMAC against using `repository_owner`, which is read from the `repository.owner.login` (or `organization.login`) field of the *same* JSON body being verified. The event handlers that actually mutate state, however, key off a *different* field of that body — `repository.full_name` (or in `StatusHandler`'s case, no repository scoping at all) — without re-validating that it belongs to the organization whose secret was used to authenticate the request.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret with: [1](#0-0) 

where `repository_owner` is: [2](#0-1) 

This means the signature is only proof that *someone who knows the webhook secret for `repository.owner.login`* sent this exact body — nothing more. It says nothing about the value of `repository.full_name` inside that same body.

Every handler that acts on the payload, however, resolves the target `Repository`/`Stack` from `repository.full_name`, e.g. the base `Handler` class: [3](#0-2) 

and `Repository.from_github_repo_name`: [4](#0-3) 

`PushHandler` triggers a GitHub sync for any stack matching that resolved repository/branch: [5](#0-4) 

`CheckSuiteHandler` schedules a check-run refresh for commits under that resolved stack: [6](#0-5) 

`StatusHandler` is worse: it doesn't even use `repository.full_name` to scope the write — it matches by raw SHA across the entire instance, spanning all organizations/stacks configured in the same Shipit deployment: [7](#0-6) 

Because Shipit explicitly supports multiple independently-onboarded GitHub organizations sharing one instance (each with its own `webhook_secret`, as shown in `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`): [8](#0-7) 

any organization admin who legitimately possesses their *own* org's `webhook_secret` can compute a valid `X-Hub-Signature` over an arbitrary JSON body that they fully control. The signature check only proves "this body was signed with OrgA's secret" — it never checks that `repository.full_name`/`repository.owner.login` inside that body is internally consistent, nor that the org whose secret validated the request actually owns the repository named in `repository.full_name`.

This breaks exactly the binding called out by the rules: *"an organization that authenticated versus the repository that is written."* The equality that should hold — `organization used to select webhook_secret == organization owning the repository the handler subsequently writes to` — is never enforced.

### Impact Explanation
An attacker who legitimately controls one GitHub organization onboarded into a shared/multi-tenant Shipit instance (and therefore knows their own `webhook_secret`) can:
- Craft a `push` event with `repository.owner.login = "OrgA"` (their own, to pass signature check) but `repository.full_name = "OrgB/victim-repo"`, forcing `PushHandler` to trigger `stack.sync_github` for a stack that belongs to a different organization.
- Craft a `check_suite` event the same way to mark check runs for `OrgB`'s commits as needing refresh, or forge a `status` event to inject fabricated commit statuses for **any** commit SHA in the entire Shipit instance regardless of organization, since `StatusHandler` performs no repository/org scoping at all.

Because deploy eligibility in Shipit can depend on required commit statuses/check runs (`Commit#required_statuses`, `blocking_statuses`), forging statuses for another organization's commits is a cross-repository write that can influence whether a deploy is considered safe/allowed — a real cross-tenant boundary violation with no legitimate write access to the victim's actual GitHub repository or Shipit stack required.

### Likelihood Explanation
This requires the specific documented multi-organization configuration (multiple GitHub Apps/orgs sharing one Shipit instance). The attacker needs no privileged access to Shipit itself and no access to the victim org's webhook secret — only the ability to compute an HMAC with their own org's secret and send an arbitrary payload. This is a realistic, low-effort attack for any Shipit operator running the officially supported multi-org mode with at least one less-trusted tenant.

### Recommendation
- Reject webhooks where `repository.owner.login` (or `organization.login`) does not match the owner segment of `repository.full_name`.
- After computing `repository_owner` for signature verification, re-derive/require that all repository-identifying fields used downstream in handlers are validated against that same verified owner — not read independently from an unvalidated portion of the payload.
- In `StatusHandler`, scope the `Commit` lookup by the repository/stack resolved from the verified organization instead of matching on `sha` alone across the whole database.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s multi-org config), each with an onboarded stack (`OrgA/repoA`, `OrgB/victim-repo`).
2. As an attacker who administers `OrgA`'s GitHub App (and therefore knows `OrgA`'s `webhook_secret`), build a JSON body for a `status` event:
   ```json
   { "sha": "<sha-of-a-commit-in-OrgB/victim-repo>", "state": "success", "context": "ci/forged",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/repoA" } }
   ```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)`.
4. POST to `/webhooks` with `X-Github-Event: status` and the computed signature.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s app, and the signature validates successfully (attacker legitimately knows this secret).
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the commit that actually belongs to `OrgB/victim-repo` — and calls `commit.create_status_from_github!(params)`, injecting a forged "success" status onto a commit in an organization the attacker does not control, potentially unblocking a deploy gated on that status.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
