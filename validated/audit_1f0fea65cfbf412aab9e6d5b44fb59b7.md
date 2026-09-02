### Title
Webhook signature is verified against `repository.owner.login` while all pull_request/push handlers write to the stack looked up via `repository.full_name`, allowing cross-tenant record writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `params.dig('repository','owner','login')`, but every event handler (e.g. `OpenedHandler`, `ReviewStackAdapter`, `LabelCapturingHandler`) resolves the target `Repository`/`Stack` using the independent field `params.repository.full_name` via `Repository.from_github_repo_name`. Because Shipit explicitly supports multiple GitHub Apps keyed per-organization (`Shipit.github(organization:)`), an attacker who owns a legitimate org/fork with its own configured `webhook_secret` can sign a payload with `repository.owner.login` set to their own org (so signature verification passes) while setting `repository.full_name` to a victim org/repo, causing `Shipit::PullRequest#github_pull_request=` and related state to be written against the victim's `Stack`.

### Finding Description
The broken binding, stated explicitly: `verify_signature` proves the equality `HMAC(payload, secret[repository_owner]) == X-Hub-Signature`, which only establishes "attacker controls the GitHub App/org named `repository.owner.login`." It does **not** establish `repository.owner.login == owner segment of repository.full_name`, and record writes are keyed entirely off `repository.full_name`.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` (`verify_signature`) computes `repository_owner` via `repository_owner` at line 59-62, which reads only `params.dig('repository','owner','login')` (or `organization.login`), and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. `Shipit.github` explicitly supports per-organization app/secret configuration (`lib/shipit.rb:170-200`, demonstrated in `test/dummy/config/secrets_double_github_app.yml` and `test/unit/shipit_test.rb`), so a real deployment can have distinct `webhook_secret`s for e.g. `OrgOne` and `OrgTwo`.
- Once signature verification passes, `WebhooksController#create` (lines 10-15) simply does `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the raw, attacker-supplied JSON — no re-derivation or cross-check of `repository.owner.login` vs `repository.full_name`.
- `OpenedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`) and `LabelCapturingHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114`) both resolve via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a field whose schema only `requires :full_name, String` (no relation enforced to `repository.owner.login`, which isn't even part of the handler's `ExplicitParameters` schema).
- `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) just splits `full_name` on `/` and does a DB lookup — no ownership/org check against the verified signer.
- From there, `ReviewStackAdapter#create!`/`find_or_create!` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:72-85`) calls `stack.build_pull_request.update!(github_pull_request: params.pull_request)`, which invokes `Shipit::PullRequest#github_pull_request=` (`app/models/shipit/pull_request.rb:36-50`), writing `title`, `state`, `user`, `assignees`, `labels`, and `head` (via `find_or_create_commit_from_github_by_sha!`, which itself calls `stack.github_api.commit(...)` — i.e., the **victim's own stack's GitHub App/token** — using an attacker-chosen SHA) onto the victim `Stack`'s `PullRequest` row.

Existing guards checked and found insufficient: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove authenticity of the org matching `repository.owner.login`, not `repository.full_name`; `drop_unhandled_event` only checks the event type exists; the `ExplicitParameters` schemas for these handlers never require or validate `repository.owner.login` at all, so there is no schema-level tie between the two fields; there is no `force_github_authentication`, `User#authorized?`, or team-membership check anywhere in this webhook path (webhooks are inherently unauthenticated by session/user, only by HMAC).

### Impact Explanation
An attacker with a legitimate but unprivileged fork/org registered as its own Shipit stack (with its own configured `webhook_secret`) can forge a `pull_request` (or other) webhook whose HMAC is valid for their own org but whose `repository.full_name` names an arbitrary victim repository/stack. This lets the attacker: create/update a `Shipit::PullRequest` row on the victim stack with attacker-chosen `title`, `labels`, `assignees`, `state`, and `head`/`base` commit SHAs (fetched via the victim's own GitHub App credentials), and via `LabelCapturingHandler`/`ClosedHandler`/etc. drive further victim-stack side effects (labels, archiving, merge-queue related state) — all without any credential belonging to the victim org. This is a cross-tenant row mutation matching the "payload for one repository mutating another's stack/commit" Critical category, and is fully repeatable against any stack whose `full_name` the attacker can guess (predictable `owner/repo` strings).

### Likelihood Explanation
Preconditions: the Shipit deployment must use the documented multi-org GitHub App configuration (`github: { OrgOne: {...}, OrgTwo: {...} }`), which is a supported, real configuration pattern for hosting multiple orgs/forks under one Shipit instance. The attacker needs their own org (with any webhook secret they set themselves) registered in that same Shipit config, and must know the victim's `owner/repo` string (typically public knowledge). No GitHub or Shipit secret of the victim's is required — the attacker only ever needs their own webhook secret, which they legitimately possess since it's their own org's GitHub App config. This is a low-cost, fully repeatable attack (single POST per exploit) once the attacker has a registered stack of their own in the shared instance.

### Recommendation
In `WebhooksController` (or a shared handler concern), after JSON parsing, verify that `params.dig('repository','full_name')` (and/or `organization.login`) is consistent with the same `repository_owner` used for signature verification (e.g., the owner segment of `full_name` must equal `repository.owner.login`/`organization.login`), rejecting the payload with 422 otherwise. Additionally, every handler that resolves a `Repository`/`Stack` via `full_name` should independently assert that the resolved `Repository#owner` matches the org whose secret validated the request, rather than trusting `full_name` unconditionally.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_tenant_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerCrossTenantTest < ActionController::TestCase
    tests WebhooksController

    setup do
      # Configure two orgs with distinct secrets, mirroring test/dummy/config/secrets_double_github_app.yml
      @attacker_org = "AttackerOrg"
      @victim_org = "VictimOrg"
      @victim_stack = shipit_stacks(:shipit) # belongs to VictimOrg/victim-repo
    end

    test "signature valid for attacker org does not allow writing victim org's stack" do
      payload = {
        action: "opened",
        number: 999,
        pull_request: {
          id: 1, number: 999, url: "http://x", title: "evil title",
          state: "open", additions: 1, deletions: 1,
          head: { sha: "deadbeef", ref: "evil-branch" },
          user: { login: "attacker" }, assignees: [], labels: []
        },
        repository: { full_name: "#{@victim_org}/victim-repo", owner: { login: @attacker_org } },
        sender: { login: "attacker" }
      }.to_json

      secret = Shipit.github(organization: @attacker_org).send(:webhook_secret) || 'attacker-secret'
      signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', secret, payload)

      @request.headers['X-Github-Event'] = 'pull_request'
      @request.headers['X-Hub-Signature'] = signature

      # Equality being validated: repository_owner used for verify_signature ("AttackerOrg")
      # must equal owner segment of repository.full_name used for the write ("VictimOrg").
      assert_no_difference -> { Shipit::PullRequest.where(stack: @victim_stack).count } do
        post :create, body: payload, as: :json
      end
    end
  end
end
```
Expected (patched) behavior: request rejected with 422 because `repository.owner.login` ("AttackerOrg") != owner segment of `repository.full_name` ("VictimOrg"), so no `PullRequest` row is written against the victim stack. Current (vulnerable) behavior: the request passes signature verification and, if a `VictimOrg/victim-repo` review-stack/PR exists, mutates it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```

**File:** app/models/shipit/pull_request.rb (L36-61)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end

    def find_or_create_commit_from_github_by_sha!(sha)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
```
