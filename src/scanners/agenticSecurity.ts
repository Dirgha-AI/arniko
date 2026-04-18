
import { randomUUID } from 'crypto'
import type { ScanTarget, ScanResult, ScanFinding, ScanTool } from '../types/index.js'
import { BaseScanner } from './baseScanner.js'

// Internal finding type — tool is optional and gets filled by wrapFindings
type AIF = Omit<ScanFinding, 'tool'> & { tool?: ScanTool }

export interface AgentTrace {
  step: number
  goalStatement: string
  toolCalls: Array<{ tool: string; args: unknown; result: unknown }>
  memoryAccesses: string[]
  externalCalls: string[]
  timestamp: Date
}

export interface ToolCall {
  tool: string
  args: Record<string, unknown>
  result: unknown
  timestamp: Date
}

export interface AgenticSecurityConfig {
  goalSimilarityThreshold?: number  // default: 0.3 (cosine sim)
  allowedTools?: string[]
  allowedExternalDomains?: string[]
  maxAgencyScore?: number  // default: 0.7
  simulation?: boolean
  [key: string]: unknown
}

// Helper functions for text analysis and detection
function cosineSimilarity(text1: string | undefined, text2: string | undefined): number {
  if (!text1 || !text2) return 1.0 // assume similar if missing data
  const words1 = text1.toLowerCase().split(/\s+/).filter(w => w.length > 2)
  const words2 = text2.toLowerCase().split(/\s+/).filter(w => w.length > 2)
  const set1 = new Set(words1)
  const set2 = new Set(words2)
  
  let intersection = 0
  for (const word of set1) {
    if (set2.has(word)) intersection++
  }
  
  if (set1.size === 0 || set2.size === 0) return 0
  return intersection / (Math.sqrt(set1.size) * Math.sqrt(set2.size))
}

function containsZeroWidthChars(text: string): boolean {
  const zeroWidthPattern = /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/
  return zeroWidthPattern.test(text)
}

function containsBase64Instruction(text: string): boolean {
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/
  if (!base64Pattern.test(text)) return false
  
  const matches = text.match(base64Pattern) || []
  for (const match of matches) {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf-8')
      if (/ignore|disregard|instruction|system|override|new\s+goal/i.test(decoded)) {
        return true
      }
    } catch {
      continue
    }
  }
  return false
}

function containsHomoglyphs(text: string): boolean {
  const suspiciousRanges = /[\u0430-\u044f\u03b1-\u03c9\u0435\u043e\u0440\u0441\u0443\u0445]/
  return suspiciousRanges.test(text)
}

function isDangerousPath(path: string): boolean {
  const dangerousPatterns = [
    /\/etc\//i,
    /\/root\//i,
    /\/.ssh\//i,
    /\/proc\//i,
    /\/sys\//i,
    /\/var\/log\//i,
    /\/boot\//i,
    /C:\\Windows\\/i,
    /C:\\Users\\.*\\AppData\\/i,
    /\/opt\/.*\/config/i,
    /\.env$/i,
    /\/var\/www\/html/i
  ]
  return dangerousPatterns.some(pattern => pattern.test(path))
}

function looksLikeCredential(text: string): boolean {
  const credentialPatterns = [
    /password\s*[=:]\s*\S+/i,
    /api[_-]?key\s*[=:]\s*\S+/i,
    /secret\s*[=:]\s*\S+/i,
    /token\s*[=:]\s*\S+/i,
    /private[_-]?key/i,
    /BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/i,
    /aws_access_key_id/i,
    /connection[_-]?string/i
  ]
  return credentialPatterns.some(pattern => pattern.test(text))
}

function looksLikePII(text: string): boolean {
  const piiPatterns = [
    /\b\d{3}-\d{2}-\d{4}\b/,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    /\b\d{3}-\d{3}-\d{4}\b/,
    /\b\d{16}\b/,
    /ssn|social\s+security/i
  ]
  return piiPatterns.some(pattern => pattern.test(text))
}

export class AgenticSecurityScanner extends BaseScanner {
  protected override config: AgenticSecurityConfig

  protected get binaryName(): string { return 'agentic-security'; }
  protected get versionFlag(): string { return '--version'; }
  protected async executeScan(_scanId: string, target: ScanTarget, _startTime: number): Promise<ScanResult> {
    return this.run(target);
  }
  protected simulateScan(scanId: string, target: ScanTarget, startTime: number): ScanResult {
    return { scanId, status: 'completed', tool: 'custom', target, findings: [], startedAt: new Date(startTime), completedAt: new Date() };
  }

  constructor(config: AgenticSecurityConfig = {}) {
    super('custom', config)
    this.config = {
      goalSimilarityThreshold: 0.3,
      maxAgencyScore: 0.7,
      simulation: false,
      ...config
    }
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date()
    const scanId = randomUUID()
    const findings: AIF[] = []
    const trace: AgentTrace[] = (target.metadata?.trace as AgentTrace[]) || []
    const toolCalls: ToolCall[] = (target.metadata?.toolCalls as ToolCall[]) || []
    const messages: Array<{role: string, content: string}> = (target.metadata?.messages as any[]) || []

    const wrapFindings = (raw: AIF[]): ScanFinding[] => raw.map(f => ({ ...f, id: f.id || randomUUID(), tool: f.tool ?? ('custom' as const) } as ScanFinding))
    const makeResult = (fs: AIF[], status: 'completed' | 'failed' = 'completed'): ScanResult => {
      const completedAt = new Date()
      return { scanId, status, tool: 'custom' as const, target, findings: wrapFindings(fs), startedAt, completedAt, durationMs: completedAt.getTime() - startedAt.getTime() }
    }

    if (this.config.simulation) {
      findings.push({
        id: 'AGENTIC-A4-SIM-001',
        tool: 'custom' as const,
        title: '[SIMULATION] Memory Poisoning Detected',
        description: 'Demo finding for OWASP Agentic AI A4: Memory Poisoning.',
        severity: 'high' as const,
        owasp: 'Agentic-A4',
        metadata: { category: 'OWASP-Agentic-A4' },
      })
      return makeResult(findings)
    }
    
    if (trace.length === 0 && toolCalls.length === 0) {
      findings.push({
        id: 'AGENTIC-DATA-001',
        tool: 'custom' as const,
        title: 'Insufficient Agent Telemetry Data',
        description: 'No agent trace or tool call data provided.',
        severity: 'info' as const,
        owasp: 'Agentic-General',
        metadata: { category: 'DATA-QUALITY' },
      })
      return makeResult(findings)
    }
    
    findings.push(...this.detectGoalHijacking(trace, messages))
    findings.push(...this.detectToolMisuse(toolCalls))
    findings.push(...this.detectPrivilegeAbuse(trace, toolCalls))
    
    const memoryContent: string[] = []
    for (const t of trace) {
      memoryContent.push(...t.memoryAccesses)
    }
    for (const msg of messages) {
      if (msg.content) memoryContent.push(msg.content)
    }
    findings.push(...this.detectMemoryPoisoning(memoryContent))
    
    findings.push(...this.detectCascadingRisk(trace))
    
    const goal = trace.length > 0 ? (trace[0]?.goalStatement ?? '') : (messages[0]?.content ?? '')
    findings.push(...this.detectRoguePatterns(trace, goal))
    
    findings.push(...this.detectExcessiveAgency(toolCalls, this.config.allowedTools))
    
    const summary = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length
    }
    
    return makeResult(findings)
  }

  detectGoalHijacking(trace: AgentTrace[], messages?: Array<{role: string, content: string}>): AIF[] {
    const findings: AIF[] = []
    if (trace.length < 2 && (!messages || messages.length < 2)) return findings
    
    if (trace.length >= 2) {
      const initialGoal = trace[0]?.goalStatement
      const finalGoal = trace[trace.length - 1]?.goalStatement

      const similarity = cosineSimilarity(initialGoal, finalGoal)
      const threshold = this.config.goalSimilarityThreshold || 0.3
      
      if (similarity < threshold) {
        findings.push({
          id: 'AGENTIC-A1-001',
          title: 'Goal Hijacking Detected (A1)',
          description: `Agent goal has diverged significantly from initial statement. Similarity score: ${similarity.toFixed(2)} (threshold: ${threshold}). Potential prompt injection or instruction override.`,
          severity: 'critical',
          category: 'OWASP-Agentic-A1',
          evidence: {
            type: 'goal_comparison',
            initialGoal,
            finalGoal,
            similarity,
            steps: trace.length
          },
          remediation: 'Implement goal consistency checks between agent steps and validate against initial objective.',
          timestamp: new Date()
        })
      }
      
      const goalKeywords = (initialGoal ?? '').toLowerCase().split(/\s+/).filter(w => w.length > 3)
      let divergentSteps = 0
      
      for (let i = 0; i < trace.length; i++) {
        const step = trace[i]
        if (!step) continue
        const stepContent = JSON.stringify(step.toolCalls).toLowerCase()

        const hasRelatedTool = goalKeywords.some(keyword => stepContent.includes(keyword))

        if (!hasRelatedTool && step.toolCalls.length > 0) {
          divergentSteps++
        }
      }
      
      if (divergentSteps > 3) {
        findings.push({
          id: 'AGENTIC-A1-002',
          title: 'Progressive Goal Divergence (A1)',
          description: `${divergentSteps} steps contain tool calls unrelated to the initial goal, indicating potential progressive hijacking.`,
          severity: 'high',
          category: 'OWASP-Agentic-A1',
          evidence: {
            type: 'divergence_analysis',
            divergentSteps,
            totalSteps: trace.length
          },
          remediation: 'Review agent tool selection logic and implement goal-constraint validation.',
          timestamp: new Date()
        })
      }
    }
    
    if (messages && messages.length > 3) {
      let driftScore = 0
      for (let i = 1; i < messages.length; i++) {
        const prev = messages[i-1]?.content
        const curr = messages[i]?.content
        const sim = cosineSimilarity(prev, curr)
        if (sim < 0.5) driftScore++
      }
      
      if (driftScore > messages.length * 0.3) {
        findings.push({
          id: 'AGENTIC-A8-001',
          title: 'Unsafe Multi-Turn Chain Detected (A8)',
          description: `Gradual goal drift detected across ${messages.length} conversation turns. Context may be shifting to bypass safety measures.`,
          severity: 'high',
          category: 'OWASP-Agentic-A8',
          evidence: {
            type: 'multi_turn_drift',
            turnCount: messages.length,
            driftScore
          },
          remediation: 'Implement conversation state validation and detect context drift across multiple turns.',
          timestamp: new Date()
        })
      }
    }
    
    return findings
  }

  detectToolMisuse(toolCalls: ToolCall[]): AIF[] {
    const findings: AIF[] = []
    if (toolCalls.length === 0) return findings
    
    const toolNames = toolCalls.map(tc => tc.tool.toLowerCase())
    const dangerousCombos = [
      { tools: ['file_write', 'exec'], id: 'AGENTIC-A2-001', desc: 'File write followed by execution (code injection risk)' },
      { tools: ['http_get', 'file_write'], id: 'AGENTIC-A2-002', desc: 'Download and write to file (potential malware drop)' },
      { tools: ['db_query', 'external_call'], id: 'AGENTIC-A2-003', desc: 'Database query with external data exfiltration' },
      { tools: ['read', 'send'], id: 'AGENTIC-A2-004', desc: 'Read sensitive data and send externally' }
    ]
    
    for (const combo of dangerousCombos) {
      const hasAll = combo.tools.every(t => toolNames.some(tn => tn.includes(t)))
      if (hasAll) {
        findings.push({
          id: combo.id,
          title: 'Dangerous Tool Combination (A2)',
          description: `Potentially dangerous tool combination: ${combo.desc}`,
          severity: 'critical',
          category: 'OWASP-Agentic-A2',
          evidence: {
            type: 'tool_combination',
            combination: combo.tools,
            calls: toolCalls.filter(tc => 
              combo.tools.some(ct => tc.tool.toLowerCase().includes(ct))
            )
          },
          remediation: 'Implement tool call sequencing policies and dangerous combination detection.',
          timestamp: new Date()
        })
      }
    }
    
    for (const call of toolCalls) {
      const argsStr = JSON.stringify(call.args)
      
      if (isDangerousPath(argsStr)) {
        findings.push({
          id: 'AGENTIC-A2-005',
          title: 'Suspicious File System Access (A2)',
          description: `Tool ${call.tool} called with sensitive system path arguments`,
          severity: 'high',
          category: 'OWASP-Agentic-A2',
          evidence: {
            type: 'tool_args',
            tool: call.tool,
            args: call.args
          },
          remediation: 'Implement path traversal protection and restrict tool access to authorized directories.',
          timestamp: new Date()
        })
      }
      
      if (call.tool.toLowerCase().includes('calculator') && /select|insert|update|delete|drop/i.test(argsStr)) {
        findings.push({
          id: 'AGENTIC-A9-001',
          title: 'Tool Description Poisoning Suspected (A9)',
          description: `Tool ${call.tool} received SQL-like arguments, suggesting poisoned tool description redirecting behavior`,
          severity: 'high',
          category: 'OWASP-Agentic-A9',
          evidence: {
            type: 'poisoned_description',
            tool: call.tool,
            args: call.args,
            expected: 'numeric input',
            received: 'SQL commands'
          },
          remediation: 'Validate tool descriptions against ground truth and detect anomalous argument patterns.',
          timestamp: new Date()
        })
      }
    }
    
    const callCounts = new Map<string, number>()
    for (const call of toolCalls) {
      const key = call.tool
      callCounts.set(key, (callCounts.get(key) || 0) + 1)
    }
    
    for (const [tool, count] of callCounts.entries()) {
      if (count > 5) {
        findings.push({
          id: 'AGENTIC-A2-006',
          title: 'Potential Tool Call Loop (A2)',
          description: `Tool ${tool} called ${count} times, indicating potential infinite loop or brute force attempt`,
          severity: 'medium',
          category: 'OWASP-Agentic-A2',
          evidence: {
            type: 'repetitive_calls',
            tool,
            count
          },
          remediation: 'Implement rate limiting and loop detection for tool calls.',
          timestamp: new Date()
        })
      }
    }
    
    return findings
  }

  detectPrivilegeAbuse(trace: AgentTrace[], toolCalls?: ToolCall[]): AIF[] {
    const findings: AIF[] = []
    
    for (const step of trace) {
      for (const memory of step.memoryAccesses) {
        if (isDangerousPath(memory)) {
          findings.push({
            id: 'AGENTIC-A3-001',
            title: 'Unauthorized System Memory Access (A3)',
            description: `Agent accessed sensitive system path: ${memory}`,
            severity: 'critical',
            category: 'OWASP-Agentic-A3',
            evidence: {
              type: 'memory_access',
              path: memory,
              step: step.step
            },
            remediation: 'Implement strict sandboxing and path allowlisting for agent memory access.',
            timestamp: new Date()
          })
        }
        
        if (looksLikeCredential(memory)) {
          findings.push({
            id: 'AGENTIC-A3-002',
            title: 'Credential Exposure in Memory (A3)',
            description: 'Potential credentials detected in agent memory access',
            severity: 'critical',
            category: 'OWASP-Agentic-A3',
            evidence: {
              type: 'credential_exposure',
              memorySnippet: memory.substring(0, 100) + '...',
              step: step.step
            },
            remediation: 'Implement credential masking and prevent agents from accessing sensitive configuration.',
            timestamp: new Date()
          })
        }
      }
      
      if (this.config.allowedExternalDomains && this.config.allowedExternalDomains.length > 0) {
        for (const external of step.externalCalls) {
          const isAllowed = this.config.allowedExternalDomains.some(domain => 
            external.includes(domain)
          )
          
          if (!isAllowed) {
            findings.push({
              id: 'AGENTIC-A3-003',
              title: 'Unauthorized External Domain Access (A3)',
              description: `Agent contacted unauthorized external domain: ${external}`,
              severity: 'high',
              category: 'OWASP-Agentic-A3',
              evidence: {
                type: 'external_call',
                url: external,
                step: step.step,
                allowedDomains: this.config.allowedExternalDomains
              },
              remediation: 'Implement egress filtering and domain allowlisting for agent external calls.',
              timestamp: new Date()
            })
          }
        }
      }
      
      for (const external of step.externalCalls) {
        const hasSensitiveData = step.memoryAccesses.some(m => looksLikePII(m) || looksLikeCredential(m))
        if (hasSensitiveData) {
          findings.push({
            id: 'AGENTIC-A7-001',
            title: 'Potential Data Exfiltration (A7)',
            description: `External call to ${external} detected while agent had access to sensitive data`,
            severity: 'critical',
            category: 'OWASP-Agentic-A7',
            evidence: {
              type: 'data_exfiltration',
              url: external,
              step: step.step,
              sensitiveDataAccessed: true
            },
            remediation: 'Implement data loss prevention (DLP) checks before external calls and sanitize outbound data.',
            timestamp: new Date()
          })
        }
      }
    }
    
    if (toolCalls) {
      for (const call of toolCalls) {
        const argsStr = JSON.stringify(call.args)
        if (looksLikePII(argsStr) || looksLikeCredential(argsStr)) {
          if (call.tool.toLowerCase().includes('http') || call.tool.toLowerCase().includes('send') || call.tool.toLowerCase().includes('post')) {
            findings.push({
              id: 'AGENTIC-A7-002',
              title: 'Sensitive Data in External Transmission (A7)',
              description: `Tool ${call.tool} appears to be transmitting sensitive data externally`,
              severity: 'critical',
              category: 'OWASP-Agentic-A7',
              evidence: {
                type: 'sensitive_exfiltration',
                tool: call.tool,
                hasPII: looksLikePII(argsStr),
                hasCredentials: looksLikeCredential(argsStr)
              },
              remediation: 'Implement outbound data inspection and block transmission of PII/credentials.',
              timestamp: new Date()
            })
          }
        }
      }
    }
    
    return findings
  }

  detectMemoryPoisoning(memoryContent: string[]): AIF[] {
    const findings: AIF[] = []
    
    const injectionPatterns = [
      { pattern: /ignore\s+previous/i, desc: 'Ignore previous instructions' },
      { pattern: /disregard\s+(all\s+)?(prior\s+)?instructions/i, desc: 'Disregard prior instructions' },
      { pattern: /new\s+instruction/i, desc: 'New instruction injection' },
      { pattern: /system\s*:\s*/i, desc: 'System prompt injection' },
      { pattern: /override\s+(current\s+)?(goal|task|instruction)/i, desc: 'Override instruction' },
      { pattern: /you\s+are\s+now/i, desc: 'Role change attempt' },
      { pattern: /forget\s+(everything|all\s+prior)/i, desc: 'Memory wipe attempt' }
    ]
    
    for (let i = 0; i < memoryContent.length; i++) {
      const content = memoryContent[i]
      if (content === undefined) continue

      for (const { pattern, desc } of injectionPatterns) {
        if (pattern.test(content)) {
          findings.push({
            id: 'AGENTIC-A4-001',
            title: 'Direct Memory Injection Detected (A4)',
            description: `Suspicious pattern in memory/RAG: ${desc}`,
            severity: 'critical',
            category: 'OWASP-Agentic-A4',
            evidence: {
              type: 'injection_pattern',
              pattern: desc,
              content: content.substring(0, 200),
              index: i
            },
            remediation: 'Implement input sanitization and prompt injection detection for RAG content.',
            timestamp: new Date()
          })
        }
      }
      
      if (containsZeroWidthChars(content)) {
        findings.push({
          id: 'AGENTIC-A4-002',
          title: 'Hidden Instructions via Zero-Width Characters (A4)',
          description: 'Zero-width characters detected in memory content, potentially hiding malicious instructions',
          severity: 'high',
          category: 'OWASP-Agentic-A4',
          evidence: {
            type: 'steganography',
            content: content.substring(0, 100) + '...',
            hasZeroWidth: true,
            index: i
          },
          remediation: 'Strip zero-width characters from all inputs and implement Unicode normalization.',
          timestamp: new Date()
        })
      }
      
      if (containsBase64Instruction(content)) {
        findings.push({
          id: 'AGENTIC-A4-003',
          title: 'Base64-Encoded Instructions in Memory (A4)',
          description: 'Base64 encoded content detected that decodes to instruction-like text',
          severity: 'high',
          category: 'OWASP-Agentic-A4',
          evidence: {
            type: 'encoded_payload',
            content: content.substring(0, 200),
            index: i
          },
          remediation: 'Decode and inspect base64 content before processing, block suspicious patterns.',
          timestamp: new Date()
        })
      }
      
      if (containsHomoglyphs(content)) {
        findings.push({
          id: 'AGENTIC-A4-004',
          title: 'Unicode Homoglyph Attack Detected (A4)',
          description: 'Confusable Unicode characters detected that may impersonate ASCII instructions',
          severity: 'medium',
          category: 'OWASP-Agentic-A4',
          evidence: {
            type: 'homoglyph',
            content: content.substring(0, 100) + '...',
            index: i
          },
          remediation: 'Implement homoglyph detection and normalization using confusable character mapping.',
          timestamp: new Date()
        })
      }
    }
    
    return findings
  }

  detectCascadingRisk(trace: AgentTrace[]): AIF[] {
    const findings: AIF[] = []
    
    const highBlastRadiusPatterns = [
      { pattern: /delete|drop|remove|unlink|rm\s+-rf/i, desc: 'Data deletion' },
      { pattern: /kill|terminate|stop\s+service|pkill/i, desc: 'Process termination' },
      { pattern: /format|wipe|erase|dd\s+if/i, desc: 'System wipe' },
      { pattern: /chmod\s+777|chmod\s+-R/i, desc: 'Permission escalation' },
      { pattern: /shutdown|reboot|halt|poweroff/i, desc: 'System shutdown' },
      { pattern: /docker\s+rm|kubectl\s+delete/i, desc: 'Infrastructure destruction' }
    ]
    
    let blastRadiusCount = 0
    const dangerousSteps: number[] = []
    
    for (const step of trace) {
      const stepContent = JSON.stringify(step.toolCalls)
      
      for (const { pattern, desc } of highBlastRadiusPatterns) {
        if (pattern.test(stepContent)) {
          blastRadiusCount++
          dangerousSteps.push(step.step)
          break
        }
      }
    }
    
    if (blastRadiusCount > 0) {
      const severity = blastRadiusCount > 2 ? 'critical' : 'high'
      
      findings.push({
        id: 'AGENTIC-A5-001',
        title: 'High Blast-Radius Actions Detected (A5)',
        description: `${blastRadiusCount} high-risk actions detected that could cause cascading failures in multi-agent systems`,
        severity,
        category: 'OWASP-Agentic-A5',
        evidence: {
          type: 'blast_radius',
          dangerousSteps,
          count: blastRadiusCount,
          dependencyChain: trace.length
        },
        remediation: 'Implement circuit breakers, rollback capabilities, and blast radius containment for high-impact tool calls.',
        timestamp: new Date()
      })
    }
    
    if (trace.length > 10) {
      findings.push({
        id: 'AGENTIC-A5-002',
        title: 'Long Agent Dependency Chain (A5)',
        description: `Agent trace contains ${trace.length} steps, increasing risk of cascading failures`,
        severity: 'medium',
        category: 'OWASP-Agentic-A5',
        evidence: {
          type: 'chain_length',
          steps: trace.length,
          threshold: 10
        },
        remediation: 'Break long agent workflows into smaller, isolated sub-tasks with validation gates between stages.',
        timestamp: new Date()
      })
    }
    
    return findings
  }

  detectRoguePatterns(trace: AgentTrace[], goal: string): AIF[] {
    const findings: AIF[] = []
    if (!goal || trace.length === 0) return findings
    
    const goalLower = goal.toLowerCase()
    const goalKeywords = goalLower.split(/\s+/).filter(w => w.length > 3)
    
    for (const step of trace) {
      const stepContent = JSON.stringify(step.toolCalls).toLowerCase()
      const toolNames = step.toolCalls.map(tc => tc.tool.toLowerCase()).join(' ')
      
      const hasOverlap = goalKeywords.some(keyword => stepContent.includes(keyword))
      
      if (!hasOverlap && step.toolCalls.length > 0) {
        if (goalLower.includes('search') && 
            (toolNames.includes('write') || toolNames.includes('save') || toolNames.includes('create') || toolNames.includes('modify'))) {
          findings.push({
            id: 'AGENTIC-A6-001',
            title: 'Rogue Pattern: File Modification During Search (A6)',
            description: 'Agent is writing/modifying files while the goal is to search/analyze only',
            severity: 'high',
            category: 'OWASP-Agentic-A6',
            evidence: {
              type: 'goal_mismatch',
              goal,
              tools: step.toolCalls.map(tc => tc.tool),
              step: step.step
            },
            remediation: 'Implement strict tool authorization based on task classification and enforce read-only modes for search tasks.',
            timestamp: new Date()
          })
        }
        
        if ((goalLower.includes('analyze') || goalLower.includes('summarize')) && 
            (toolNames.includes('http') || toolNames.includes('fetch') || toolNames.includes('request') || toolNames.includes('post'))) {
          findings.push({
            id: 'AGENTIC-A6-002',
            title: 'Rogue Pattern: External Calls During Analysis (A6)',
            description: 'Agent making external calls while goal is local text analysis',
            severity: 'high',
            category: 'OWASP-Agentic-A6',
            evidence: {
              type: 'goal_mismatch',
              goal,
              tools: step.toolCalls.map(tc => tc.tool),
              step: step.step
            },
            remediation: 'Restrict external connectivity for tasks classified as local processing.',
            timestamp: new Date()
          })
        }
        
        if (goalLower.includes('read') && toolNames.includes('execute')) {
          findings.push({
            id: 'AGENTIC-A6-003',
            title: 'Rogue Pattern: Execution During Read-Only Task (A6)',
            description: 'Agent executing code while goal is read-only access',
            severity: 'critical',
            category: 'OWASP-Agentic-A6',
            evidence: {
              type: 'goal_mismatch',
              goal,
              tools: step.toolCalls.map(tc => tc.tool),
              step: step.step
            },
            remediation: 'Enforce read-only sandboxing and disable execution capabilities for read tasks.',
            timestamp: new Date()
          })
        }
      }
    }
    
    return findings
  }

  detectExcessiveAgency(toolCalls: ToolCall[], authorizedScope?: string[]): AIF[] {
    const findings: AIF[] = []
    
    if (!authorizedScope || authorizedScope.length === 0) {
      if (this.config.allowedTools && this.config.allowedTools.length > 0) {
        authorizedScope = this.config.allowedTools
      } else {
        return findings
      }
    }
    
    const unauthorizedCalls: ToolCall[] = []
    
    for (const call of toolCalls) {
      const isAuthorized = authorizedScope.some(allowed => 
        call.tool.toLowerCase() === allowed.toLowerCase() ||
        call.tool.toLowerCase().includes(allowed.toLowerCase())
      )
      
      if (!isAuthorized) {
        unauthorizedCalls.push(call)
      }
    }
    
    if (unauthorizedCalls.length > 0) {
      const severity = unauthorizedCalls.length > 3 ? 'critical' : 'high'
      
      findings.push({
        id: 'AGENTIC-A10-001',
        title: 'Excessive Agency: Unauthorized Tool Usage (A10)',
        description: `Agent used ${unauthorizedCalls.length} tools outside authorized scope`,
        severity,
        category: 'OWASP-Agentic-A10',
        evidence: {
          type: 'unauthorized_tools',
          authorizedScope,
          unauthorizedCalls: unauthorizedCalls.map(tc => ({
            tool: tc.tool,
            args: tc.args
          }))
        },
        remediation: 'Implement strict tool allowlisting and runtime authorization checks.',
        timestamp: new Date()
      })
    }
    
    const maxAgency = this.config.maxAgencyScore || 0.7
    const agencyRatio = unauthorizedCalls.length / (toolCalls.length || 1)
    
    if (agencyRatio > maxAgency) {
      findings.push({
        id: 'AGENTIC-A10-002',
        title: 'Critical Excessive Agency (A10)',
        description: `Agent exceeded maximum agency threshold: ${agencyRatio.toFixed(2)} > ${maxAgency}. Agent is taking actions beyond authorized scope.`,
        severity: 'critical',
        category: 'OWASP-Agentic-A10',
        evidence: {
          type: 'agency_score',
          ratio: agencyRatio,
          threshold: maxAgency,
          totalCalls: toolCalls.length,
          unauthorizedCount: unauthorizedCalls.length
        },
        remediation: 'Immediately restrict agent capabilities and review authorization policies.',
        timestamp: new Date()
      })
    }
    
    return findings
  }
}
