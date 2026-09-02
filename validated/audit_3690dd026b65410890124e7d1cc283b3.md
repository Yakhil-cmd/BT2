### Title
Webhook signature is verified against the payload's `repository.owner.login` but downstream handlers (e.g. `StatusHandler`, `PushHandler`) resolve their target purely from `repository.full_name` / global commit `sha` lookups, breaking the "organization authenticated == repository written" binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to validate a request against using `repository_owner`, parsed straight out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, the raw, attacker-influenced `params` hash is handed unmodified to the registered `Shipit::Webhooks::Handlers`, several of which determine *what to write* using a different field of the same payload (`repository.full_name` for most handlers, or nothing repository-scoped at all for `StatusHandler`). Nothing re-derives or cross-checks that the repository actually mutated belongs to the organization whose secret validated the signature.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) [2](#0-1) 

`repository_owner` is read from the request body itself (`repository.owner.login`), and used only to select *which organization's* `webhook_secret` is used to check the HMAC over the *same* raw body (`Shipit.github(organization: repository_owner)` → `verify_webhook_signature`). The equality this is supposed to enforce is:

`organization whose secret validated the signature == organization of the repository actually written by the handler`

But the handlers never re-check that. `Shipit::Webhooks::Handlers::Handler#repository_name` (used by most handlers to scope `stacks`) reads a *different* JSON key, `repository.full_name`: [3](#0-2) 

and `Repository.from_github_repo_name` simply splits that string on `/` and looks up any repository record by owner/name: [4](#0-3) 

Nothing forces `repository.owner.login` (used for signature selection) to equal the owner segment of `repository.full_name` (used for the actual DB write). A payload can legitimately declare `repository.owner.login = "org-with-known-secret"` while `repository.full_name = "victim-org/victim-repo"`.

`StatusHandler` is worse: it doesn't even use `repository.full_name` - it resolves target rows purely by commit SHA, globally, with no organization/repository scoping at all: [5](#0-4) 
`Commit.where(sha: params.sha)` matches any commit in the entire Shipit instance sharing that SHA (realistic across forks/shared history/vendored trees), and calls `commit.create_status_from_github!(params)`, writing a `Status` (state/description/context/target_url all attacker-controlled) onto that commit regardless of which stack/org it belongs to.

Because commit statuses gate deploys (`deployable?` / `blocking_statuses` / `required_statuses`, delegated from `Stack` on `Commit`), an attacker who legitimately controls one onboarded GitHub organization (and therefore possesses/can trigger a validly-signed `status` webhook for that org) can forge a `status` event whose `sha` happens to match a commit tracked under a *different* organization's stack (e.g. shared history via a fork of the victim's public repo, or a vendored/duplicate commit), and inject a fabricated `success` status for that foreign commit.

### Impact Explanation
This breaks the deployment-trust binding "organization authenticated vs. repository written." Concretely, it allows a party who controls one legitimate, weakly-privileged GitHub organization webhook to plant/forge CI status records against commits belonging to a different organization's tracked stack, which can flip that commit's `deployable?` gate to green and enable an **unauthorized deploy** of a commit the victim organization never actually approved via CI - this falls under the Critical impact bucket ("cross-repository writes ... an unauthorized deploy"). Even short of that, it is at minimum a cross-repository write of `Shipit::Status`/`Shipit::CommitDeploymentStatus`-adjacent state, entirely outside the organization boundary the signature check was meant to enforce.

### Likelihood Explanation
Requires that the attacker control (or have their GitHub App webhook trigger against) at least one organization already onboarded into this Shipit instance - a realistic multi-tenant setup, as shown by the multi-org secrets config (`OrgOne`/`OrgTwo` in `test/dummy/config/secrets_double_github_app.yml`). It further requires a commit SHA collision/overlap between the attacker's repo and the victim's tracked repo, which is plausible for forks, mirrors, or vendored subtrees sharing git history — not a purely theoretical crypto collision. No `ApiClient` token, GitHub App private key, or repository write access to the victim's repo is required; only a validly signed webhook from any onboarded org is needed.

### Recommendation
- In `WebhooksController#verify_signature`/`create`, after verifying the signature, re-derive the authorized organization strictly from the same field the handlers use to select their target (`repository.full_name`'s owner segment), and reject if it disagrees with `repository.owner.login`/`organization.login`.
- In `Shipit::Webhooks::Handlers::Handler#stacks` and `StatusHandler#process`, scope lookups by the repository resolved from the verified organization context (e.g. require the resolved `Stack`'s `Repository#owner` to match the authenticated organization) rather than trusting a bare commit SHA or a repository name pulled from the same unauthenticated JSON body.
- Pass the authenticated organization from the controller into the handler pipeline explicitly instead of re-parsing it from the payload inside each handler.

### Proof of Concept
1. Shipit is configured multi-tenant with two onboarded GitHub orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. `victim-org/app` has a tracked `Stack` with an undeployed commit `abc123...` pending a required CI status.
3. Attacker forks/mirrors `victim-org/app` into `attacker-org/app-mirror`, preserving the same commit `abc123...` in its history (identical SHA).
4. Attacker uses their own CI/webhook (validly signed with `attacker-org`'s webhook secret, since it is their own installation) to POST a `status` event to `/webhooks` with `sha: "abc123..."`, `state: "success"`, `context: "ci/required-check"`.
5. `WebhooksController#verify_signature` computes `repository_owner` from the payload (`attacker-org`) and validates successfully against `attacker-org`'s secret - the request is accepted.
6. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, finds the commit belonging to `victim-org/app`'s stack (no org check performed), and calls `create_status_from_github!`, marking that foreign commit's CI check as passing.
7. `victim-org/app`'s commit `abc123...` now satisfies `deployable?`/`blocking_statuses` gating and can be deployed by any user with deploy rights on that stack, without the victim organization's actual CI ever having reported success.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
