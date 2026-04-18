export function generateGitHubAction(c: {scanTypes: string[], failOn: 'critical'|'high'|'medium', schedule?: string}): string {
return `name: Arniko
on:
  push: {branches: [main]}
  pull_request: {branches: [main]}${c.schedule?`\n  schedule: {cron: '${c.schedule}'}`:''}
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: {contents: read, security-events: write, pull-requests: write}
    steps:
    - uses: actions/checkout@v4
    - run: curl -fsSL https://arniko.io/install | sh
    - run: arniko scan --types ${c.scanTypes.join(',')} --fail-on ${c.failOn} --sarif arniko.sarif --markdown arniko.md
    - uses: github/codeql-action/upload-sarif@v3
      if: always()
      with: {sarif_file: arniko.sarif}
    - if: github.event_name=='pull_request'
      uses: actions/github-script@v7
      with: {script: 'const fs=require("fs");github.rest.issues.createComment({...context.repo,issue_number:context.issue.number,body:"**Arniko Scan**\\n"+fs.readFileSync("arniko.md","utf8")});'}`;
}

export function generateGitLabCI(c: {scanTypes: string[], failOn: 'critical'|'high'|'medium', schedule?: string}): string {
return `${c.schedule?`schedule:\n  - cron: "${c.schedule}"\n`:''}stages: [scan]
arniko:
  stage: scan
  image: alpine/curl:latest
  before_script: [curl -fsSL https://arniko.io/install | sh]
  script: [arniko scan --types ${c.scanTypes.join(',')} --fail-on ${c.failOn} --sarif gl-sast-report.sarif --json arniko.json]
  artifacts:
    reports: {sast: gl-sast-report.sarif}
    paths: [arniko.json]
  rules:
  - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  - if: $CI_COMMIT_BRANCH == "main"
  after_script:
  - 'curl -H "PRIVATE-TOKEN:$GITLAB_TOKEN" -X POST "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" -d "body=Arniko findings: $(cat arniko.json | jq -r .summary)" || true'`;
}
