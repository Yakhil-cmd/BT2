### Title
Cross-organization webhook forgery due to signature verification keying on `repository.owner.login` while handlers act on `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
This is a genuine analog of the reported class of bug: a value used to satisfy a security check (`totalDuration`/signature) is tracked/derived from one field, while the value that is actually acted upon downstream is a different, attacker-influenced field from the same untrusted structure. In Shipit, the HMAC signature verification for a GitHub webhook is checked against the secret of the GitHub App selected via `repository_owner` (`repository.owner.login` or `organization.login`), but every event handler resolves the target `Repository`/`Stack` using an entirely different field, `repository.full_name` [1](#0-0) [2](#0-1) [3](#0-2) .

### Finding Description
The equality that must hold is: **the organization whose secret authenticated the signature == the owner of the repository the handler subsequently writes to**. Shipit supports hosting multiple GitHub Apps/organizations from one installation, each with its own `webhook_secret`, selected by `Shipit.github(organization:)` [4](#0-3) [5](#0-4) .

`verify_signature` picks the App/secret to check the HMAC against using `repository_owner`, which is read straight from the (as-yet-unverified) JSON body:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Once the signature check passes (i.e., `github_app.verify_webhook_signature` succeeds for the App selected by `repository_owner`) [1](#0-0) , the raw JSON is dispatched to handlers, all of which resolve which `Repository`/`Stack` to mutate using a *different* field, `repository.full_name`, via `Handler#repository_name`:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

This is used directly by `PushHandler#stacks` (triggers `stack.sync_github`) [7](#0-6)  and by `PullRequest::OpenedHandler#repository` (drives review-stack provisioning) [8](#0-7) , among other handlers.

Nothing in the controller or `Handler` base class checks that `repository.owner.login` (the field used to pick the verifying secret) is consistent with `repository.full_name` (the field used to select the target repository/stack). Since HMAC verification only proves "this body was signed by *some* known App's secret," a party who knows Org A's webhook secret (e.g., an admin of Org A's own GitHub App/organization, who is an unprivileged party with respect to Org B) can craft a JSON payload where `repository.owner.login = "A"` (so verification succeeds against A's registered secret) but `repository.full_name = "B/victim-repo"`. This breaks the intended equality: authenticated-organization == acted-upon-repository-owner.

### Impact Explanation
If Shipit is configured to host multiple organizations (a documented, supported configuration, see `secrets_double_github_app.yml` / `Shipit.github(organization:)`), an attacker who legitimately controls Org A's GitHub App webhook secret can forge push/pull_request/status/membership events that are accepted as valid and dispatched against stacks belonging to Org B's repositories. Depending on the handler reached, this can trigger unauthorized `GithubSyncJob` runs, review-stack provisioning/deprovisioning, commit status writes, or membership changes on a completely different organization's stacks — a cross-repository/cross-tenant write performed without ever holding credentials for the victim organization.

### Likelihood Explanation
This requires the Shipit instance to be configured with more than one GitHub App/organization (a supported but non-default configuration) and requires the attacker to control one of those organizations' own webhook secret (which is a low bar for that org's admins, and does not require any Shipit session, API token, or access to the victim org). Given that setup, forging the payload is a single crafted HTTP POST with a valid HMAC for the attacker's own org.

### Recommendation
After signature verification succeeds, cross-validate that `repository.owner.login` (or `organization.login`) used to select the verifying App actually matches the owner segment of `repository.full_name` before dispatching to handlers; reject the webhook (422) on mismatch. More robustly, do not trust any organization-derived field from the unverified body to select the verification secret — bind the webhook endpoint/secret to a specific, pre-registered organization/App rather than deriving it from attacker-controlled payload contents.

### Proof of Concept
1. Configure Shipit with two organizations, `A` and `B`, each with a distinct `github.webhook_secret` (as in `secrets_double_github_app.yml`), and stacks under `B/victim-repo`.
2. As an administrator of Org A's own GitHub App (holds `A`'s webhook secret only), craft a `push` event payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "A" }, "full_name": "B/victim-repo" }
}
```
3. Compute `X-Hub-Signature` using Org A's `webhook_secret` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "A")` and the signature validates [1](#0-0) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` lookup uses `repository.full_name` = `"B/victim-repo"` [3](#0-2) [7](#0-6) , causing a `GithubSyncJob`/deploy-eligible sync to run against Org B's stack despite the request only having been authenticated for Org A.

**Uncertainty:** I could not fully verify from the indexed code whether every deployment of Shipit in practice hosts multiple organizations behind one instance (this is an opt-in configuration), nor could I trace every downstream handler's write path to confirm which specific handler yields the highest-severity effect (e.g., unauthorized deploy vs. just a sync/provisioning action) without a live multi-org test setup. If the user needs the exhaustive list of impacted handlers or confirmation this affects a specific production configuration, a full Devin session with repository access would allow enumerating all `Shipit::Webhooks::Handlers::*` classes and their write paths.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
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
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
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
