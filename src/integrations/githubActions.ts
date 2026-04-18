
export interface GithubActionsConfig {
  arnikoUrl: string;
  apiKey?: string;
  scanOn?: Array<'push' | 'pull_request' | 'schedule'>;
  tools?: string[];
  failOnSeverity?: 'critical' | 'high' | 'medium' | 'low';
  uploadSarif?: boolean;
}

export class GithubActionsIntegration {
  private static buildTriggers(scanOn?: Array<'push' | 'pull_request' | 'schedule'>): string {
    const events = scanOn ?? ['push', 'pull_request'];
    return events.map(e => {
      if (e === 'schedule') return '  schedule:\n    - cron: \'0 0 * * *\'';
      return `  ${e}:\n    branches: [main, master]`;
    }).join('\n');
  }

  static generateWorkflow(config: GithubActionsConfig): string {
    const triggers = this.buildTriggers(config.scanOn);
    const tools = config.tools?.join(',') || 'semgrep,trufflehog,gitleaks';
    const failOnSeverity = config.failOnSeverity || 'high';
    const uploadSarif = config.uploadSarif !== false;
    const arnikoUrl = config.arnikoUrl.replace(/\/$/, '');

    return `name: Arniko Security Scan

on:
${triggers}

jobs:
  arniko-scan:
    name: Run Arniko Security Scan
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
      pull-requests: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Arniko Scan
        id: arniko-scan
        env:
          ARNIKO_API_KEY: \${{ secrets.ARNIKO_API_KEY }}
        run: |
          echo "Starting Arniko security scan..."
          
          # Trigger scan
          SCAN_RESPONSE=$(curl -s -X POST "${arnikoUrl}/scans" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{
              "target": "\${{ github.repository }}",
              "ref": "\${{ github.ref }}",
              "commit": "\${{ github.sha }}",
              "tools": [${tools.split(',').map(t => `"${t.trim()}"`).join(', ')}],
              "metadata": {
                "repository": "\${{ github.repository }}",
                "workflow": "\${{ github.workflow }}",
                "run_id": "\${{ github.run_id }}"
              }
            }')
          
          SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.id')
          if [ "$SCAN_ID" == "null" ] || [ -z "$SCAN_ID" ]; then
            echo "Failed to start scan: $SCAN_RESPONSE"
            exit 1
          fi
          
          echo "Scan ID: $SCAN_ID"
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

      - name: Poll for Scan Completion
        id: poll-scan
        env:
          ARNIKO_API_KEY: \${{ secrets.ARNIKO_API_KEY }}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          MAX_ATTEMPTS=60
          ATTEMPT=0
          
          while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
            STATUS_RESPONSE=$(curl -s -X GET "${arnikoUrl}/scans/$SCAN_ID" \\
              -H "Authorization: Bearer $ARNIKO_API_KEY")
            
            STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
            echo "Attempt $((ATTEMPT+1))/$MAX_ATTEMPTS - Status: $STATUS"
            
            if [ "$STATUS" == "completed" ]; then
              echo "Scan completed successfully"
              echo "status=completed" >> $GITHUB_OUTPUT
              break
            elif [ "$STATUS" == "failed" ]; then
              echo "Scan failed"
              exit 1
            fi
            
            ATTEMPT=$((ATTEMPT+1))
            sleep 10
          done
          
          if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
            echo "Scan timed out"
            exit 1
          fi

      - name: Download SARIF Report
        if: ${uploadSarif ? 'always()' : 'false'}
        id: download-sarif
        env:
          ARNIKO_API_KEY: \${{ secrets.ARNIKO_API_KEY }}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          SARIF_FILE="arniko-results.sarif"
          
          curl -s -X GET "${arnikoUrl}/scans/$SCAN_ID/sarif" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY" \\
            -o $SARIF_FILE
          
          if [ -f "$SARIF_FILE" ] && [ -s "$SARIF_FILE" ]; then
            echo "SARIF report downloaded successfully"
            echo "sarif_file=$SARIF_FILE" >> $GITHUB_OUTPUT
          else
            echo "No SARIF report available"
            echo "sarif_file=" >> $GITHUB_OUTPUT
          fi

      - name: Upload SARIF to GitHub
        if: ${uploadSarif ? 'steps.download-sarif.outputs.sarif_file != \'\'' : 'false'}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: \${{ steps.download-sarif.outputs.sarif_file }}
          category: arniko-security-scan

      - name: Check Severity Threshold
        if: always()
        env:
          ARNIKO_API_KEY: \${{ secrets.ARNIKO_API_KEY }}
          FAIL_ON_SEVERITY: ${failOnSeverity}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          
          # Get findings summary
          FINDINGS=$(curl -s -X GET "${arnikoUrl}/scans/$SCAN_ID/findings" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY")
          
          # Check severity counts based on threshold
          SEVERITY_ORDER=("critical" "high" "medium" "low")
          THRESHOLD_INDEX=-1
          
          for i in "\${!SEVERITY_ORDER[@]}"; do
            if [ "\${SEVERITY_ORDER[$i]}" == "$FAIL_ON_SEVERITY" ]; then
              THRESHOLD_INDEX=$i
              break
            fi
          done
          
          SHOULD_FAIL=false
          for ((i=0; i<=$THRESHOLD_INDEX; i++)); do
            SEVERITY="\${SEVERITY_ORDER[$i]}"
            COUNT=$(echo $FINDINGS | jq -r ".summary[\"$SEVERITY\"] // 0")
            if [ "$COUNT" -gt 0 ]; then
              echo "Found $COUNT $SEVERITY severity issues"
              SHOULD_FAIL=true
            fi
          done
          
          if [ "$SHOULD_FAIL" == "true" ]; then
            echo "Failing workflow due to findings at or above $FAIL_ON_SEVERITY severity"
            exit 1
          else
            echo "No findings at or above $FAIL_ON_SEVERITY severity"
          fi
`;
  }

  static generateReusableWorkflow(config: GithubActionsConfig): string {
    const tools = config.tools?.join(',') || 'semgrep,trufflehog,gitleaks';
    const failOnSeverity = config.failOnSeverity || 'high';
    const uploadSarif = config.uploadSarif !== false;
    const arnikoUrl = config.arnikoUrl.replace(/\/$/, '');

    return `name: Arniko Security Scan (Reusable)

on:
  workflow_call:
    inputs:
      arniko_url:
        description: 'Arniko API URL'
        required: true
        type: string
        default: '${arnikoUrl}'
      tools:
        description: 'Comma-separated list of security tools to run'
        required: false
        type: string
        default: '${tools}'
      fail_on_severity:
        description: 'Minimum severity to fail the build (critical, high, medium, low)'
        required: false
        type: string
        default: '${failOnSeverity}'
      upload_sarif:
        description: 'Upload SARIF results to GitHub Security tab'
        required: false
        type: boolean
        default: ${uploadSarif}
    secrets:
      arniko_api_key:
        description: 'Arniko API Key'
        required: true

jobs:
  arniko-scan:
    name: Run Arniko Security Scan
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
      pull-requests: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Arniko Scan
        id: arniko-scan
        env:
          ARNIKO_API_KEY: \${{ secrets.arniko_api_key }}
        run: |
          echo "Starting Arniko security scan..."
          
          TOOLS_JSON=$(echo "\${{ inputs.tools }}" | tr ',' '\\n' | jq -R . | jq -s .)
          
          SCAN_RESPONSE=$(curl -s -X POST "\${{ inputs.arniko_url }}/scans" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d "{
              \\"target\\": \\"\${{ github.repository }}\\",
              \\"ref\\": \\"\${{ github.ref }}\\",
              \\"commit\\": \\"\${{ github.sha }}\\",
              \\"tools\\": $TOOLS_JSON,
              \\"metadata\\": {
                \\"repository\\": \\"\${{ github.repository }}\\",
                \\"workflow\\": \\"\${{ github.workflow }}\\",
                \\"run_id\\": \\"\${{ github.run_id }}\\"
              }
            }")
          
          SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.id')
          if [ "$SCAN_ID" == "null" ] || [ -z "$SCAN_ID" ]; then
            echo "Failed to start scan: $SCAN_RESPONSE"
            exit 1
          fi
          
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

      - name: Poll for Scan Completion
        id: poll-scan
        env:
          ARNIKO_API_KEY: \${{ secrets.arniko_api_key }}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          MAX_ATTEMPTS=60
          ATTEMPT=0
          
          while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
            STATUS_RESPONSE=$(curl -s -X GET "\${{ inputs.arniko_url }}/scans/$SCAN_ID" \\
              -H "Authorization: Bearer $ARNIKO_API_KEY")
            
            STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
            echo "Attempt $((ATTEMPT+1))/$MAX_ATTEMPTS - Status: $STATUS"
            
            if [ "$STATUS" == "completed" ]; then
              echo "status=completed" >> $GITHUB_OUTPUT
              break
            elif [ "$STATUS" == "failed" ]; then
              exit 1
            fi
            
            ATTEMPT=$((ATTEMPT+1))
            sleep 10
          done
          
          if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
            exit 1
          fi

      - name: Download SARIF Report
        if: \${{ inputs.upload_sarif && always() }}
        id: download-sarif
        env:
          ARNIKO_API_KEY: \${{ secrets.arniko_api_key }}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          SARIF_FILE="arniko-results.sarif"
          
          curl -s -X GET "\${{ inputs.arniko_url }}/scans/$SCAN_ID/sarif" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY" \\
            -o $SARIF_FILE
          
          if [ -f "$SARIF_FILE" ] && [ -s "$SARIF_FILE" ]; then
            echo "sarif_file=$SARIF_FILE" >> $GITHUB_OUTPUT
          fi

      - name: Upload SARIF to GitHub
        if: \${{ inputs.upload_sarif && steps.download-sarif.outputs.sarif_file != '' }}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: \${{ steps.download-sarif.outputs.sarif_file }}
          category: arniko-security-scan

      - name: Check Severity Threshold
        if: always()
        env:
          ARNIKO_API_KEY: \${{ secrets.arniko_api_key }}
        run: |
          SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
          FINDINGS=$(curl -s -X GET "\${{ inputs.arniko_url }}/scans/$SCAN_ID/findings" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY")
          
          SEVERITY_ORDER=("critical" "high" "medium" "low")
          THRESHOLD_INDEX=-1
          FAIL_ON="\${{ inputs.fail_on_severity }}"
          
          for i in "\${!SEVERITY_ORDER[@]}"; do
            if [ "\${SEVERITY_ORDER[$i]}" == "$FAIL_ON" ]; then
              THRESHOLD_INDEX=$i
              break
            fi
          done
          
          SHOULD_FAIL=false
          for ((i=0; i<=$THRESHOLD_INDEX; i++)); do
            SEVERITY="\${SEVERITY_ORDER[$i]}"
            COUNT=$(echo $FINDINGS | jq -r ".summary[\"$SEVERITY\"] // 0")
            if [ "$COUNT" -gt 0 ]; then
              echo "Found $COUNT $SEVERITY severity issues"
              SHOULD_FAIL=true
            fi
          done
          
          if [ "$SHOULD_FAIL" == "true" ]; then
            exit 1
          fi
`;
  }

  static generateActionYml(config: GithubActionsConfig): string {
    const tools = config.tools?.join(',') || 'semgrep,trufflehog,gitleaks';
    const failOnSeverity = config.failOnSeverity || 'high';
    const uploadSarif = config.uploadSarif !== false;
    const arnikoUrl = config.arnikoUrl.replace(/\/$/, '');

    return `name: 'Arniko Security Scan'
description: 'AI-powered security scanning with OWASP Agentic AI Top 10 coverage'
author: 'Dirgha AI'
branding:
  icon: 'shield'
  color: 'blue'

inputs:
  arniko_url:
    description: 'Arniko API URL (e.g., https://api.dirgha.ai/api/arniko)'
    required: true
    default: '${arnikoUrl}'
  api_key:
    description: 'Arniko API key (store as GitHub secret)'
    required: true
  tools:
    description: 'Comma-separated list of security tools to run'
    required: false
    default: '${tools}'
  fail_on_severity:
    description: 'Minimum severity to fail the build (critical, high, medium, low)'
    required: false
    default: '${failOnSeverity}'
  upload_sarif:
    description: 'Upload SARIF results to GitHub Security tab'
    required: false
    default: '${uploadSarif}'

runs:
  using: 'composite'
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Run Arniko Scan
      id: arniko-scan
      shell: bash
      env:
        ARNIKO_API_KEY: \${{ inputs.api_key }}
      run: |
        echo "Starting Arniko security scan..."
        
        TOOLS_JSON=$(echo "\${{ inputs.tools }}" | tr ',' '\\n' | jq -R . | jq -s .)
        
        SCAN_RESPONSE=$(curl -s -X POST "\${{ inputs.arniko_url }}/scans" \\
          -H "Authorization: Bearer $ARNIKO_API_KEY" \\
          -H "Content-Type: application/json" \\
          -d "{
            \\"target\\": \\"\${{ github.repository }}\\",
            \\"ref\\": \\"\${{ github.ref }}\\",
            \\"commit\\": \\"\${{ github.sha }}\\",
            \\"tools\\": $TOOLS_JSON,
            \\"metadata\\": {
              \\"repository\\": \\"\${{ github.repository }}\\",
              \\"workflow\\": \\"\${{ github.workflow }}\\",
              \\"run_id\\": \\"\${{ github.run_id }}\\"
            }
          }")
        
        SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.id')
        if [ "$SCAN_ID" == "null" ] || [ -z "$SCAN_ID" ]; then
          echo "Failed to start scan: $SCAN_RESPONSE"
          exit 1
        fi
        
        echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

    - name: Poll for Scan Completion
      id: poll-scan
      shell: bash
      env:
        ARNIKO_API_KEY: \${{ inputs.api_key }}
      run: |
        SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
        MAX_ATTEMPTS=60
        ATTEMPT=0
        
        while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
          STATUS_RESPONSE=$(curl -s -X GET "\${{ inputs.arniko_url }}/scans/$SCAN_ID" \\
            -H "Authorization: Bearer $ARNIKO_API_KEY")
          
          STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
          echo "Attempt $((ATTEMPT+1))/$MAX_ATTEMPTS - Status: $STATUS"
          
          if [ "$STATUS" == "completed" ]; then
            echo "status=completed" >> $GITHUB_OUTPUT
            break
          elif [ "$STATUS" == "failed" ]; then
            exit 1
          fi
          
          ATTEMPT=$((ATTEMPT+1))
          sleep 10
        done
        
        if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
          exit 1
        fi

    - name: Download SARIF Report
      if: \${{ inputs.upload_sarif == 'true' && always() }}
      id: download-sarif
      shell: bash
      env:
        ARNIKO_API_KEY: \${{ inputs.api_key }}
      run: |
        SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
        SARIF_FILE="arniko-results.sarif"
        
        curl -s -X GET "\${{ inputs.arniko_url }}/scans/$SCAN_ID/sarif" \\
          -H "Authorization: Bearer $ARNIKO_API_KEY" \\
          -o $SARIF_FILE
        
        if [ -f "$SARIF_FILE" ] && [ -s "$SARIF_FILE" ]; then
          echo "sarif_file=$SARIF_FILE" >> $GITHUB_OUTPUT
        fi

    - name: Upload SARIF to GitHub
      if: \${{ inputs.upload_sarif == 'true' && steps.download-sarif.outputs.sarif_file != '' }}
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: \${{ steps.download-sarif.outputs.sarif_file }}
        category: arniko-security-scan

    - name: Check Severity Threshold
      if: always()
      shell: bash
      env:
        ARNIKO_API_KEY: \${{ inputs.api_key }}
      run: |
        SCAN_ID="\${{ steps.arniko-scan.outputs.scan_id }}"
        FINDINGS=$(curl -s -X GET "\${{ inputs.arniko_url }}/scans/\${SCAN_ID}/findings" -H "x-api-key: \${ARNIKO_API_KEY}")
        CRITICAL=$(echo "$FINDINGS" | jq '.summary.bySeverity.critical // 0')
        HIGH=$(echo "$FINDINGS" | jq '.summary.bySeverity.high // 0')
        echo "Critical: $CRITICAL, High: $HIGH"
        if [ "$CRITICAL" -gt "0" ]; then echo "Critical findings detected" && exit 1; fi
`;
  }

  static generateReadme(config?: Partial<GithubActionsConfig>): string {
    return `# Arniko Security Scan Action

AI-powered security scanning with OWASP Agentic AI Top 10 coverage.

## Usage

\`\`\`yaml
- uses: dirgha-ai/arniko-scan@v1
  with:
    arniko_url: https://api.dirgha.ai/api/arniko
    api_key: \${{ secrets.ARNIKO_API_KEY }}
    tools: semgrep,trufflehog,gitleaks
    fail_on_severity: high
\`\`\`

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| arniko_url | Arniko API URL | Yes | — |
| api_key | API key (GitHub secret) | Yes | — |
| tools | Comma-separated scanner list | No | semgrep,trufflehog,gitleaks |
| fail_on_severity | Fail on this severity+ | No | high |
`;
  }
}

export default GithubActionsIntegration;
