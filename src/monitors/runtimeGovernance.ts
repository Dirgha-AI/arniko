
import { randomUUID } from 'node:crypto'

export interface AgentBaseline {
  taskType: string
  expectedTools: string[]           // tools expected for this task type
  expectedExternalDomains: string[] // domains agent is expected to call
  avgToolCallsPerTask: number
  maxToolCallsPerTask: number
  avgDurationMs: number
  learningCount: number             // how many examples this baseline is based on
}

export interface GovernanceAlert {
  alertId: string
  taskType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  rule: string                      // which rule was violated
  description: string
  evidence: Record<string, unknown>
  timestamp: Date
}

export type EnforcementAction = 'warn' | 'pause' | 'terminate'

export interface GovernanceConfig {
  strictMode?: boolean              // terminate on any violation (default: false)
  learningMode?: boolean            // only learn, don't alert (default: true initially)
  maxUnknownTools?: number          // max tools not in baseline before alerting (default: 2)
  maxExternalDomains?: number       // max unknown external calls (default: 3)
  dbPath?: string                   // path to SQLite db (default: ':memory:')
}

export class BaselineStore {
  private db: any
  private fallbackMap: Map<string, AgentBaseline> = new Map()
  private useFallback: boolean = false

  constructor(dbPath: string) {
    try {
      const Database = require('better-sqlite3')
      this.db = new Database(dbPath)
      this.initTable()
      this.useFallback = false
    } catch (err) {
      console.warn('better-sqlite3 not available, falling back to in-memory Map')
      this.useFallback = true
    }
  }

  private initTable(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agent_baselines (
        task_type TEXT PRIMARY KEY,
        expected_tools TEXT,
        expected_external_domains TEXT,
        avg_tool_calls REAL,
        max_tool_calls INTEGER,
        avg_duration_ms REAL,
        learning_count INTEGER
      )
    `)
  }

  save(baseline: AgentBaseline): void {
    if (this.useFallback) {
      this.fallbackMap.set(baseline.taskType, baseline)
      return
    }
    
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO agent_baselines 
      (task_type, expected_tools, expected_external_domains, avg_tool_calls, max_tool_calls, avg_duration_ms, learning_count)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    
    stmt.run(
      baseline.taskType,
      JSON.stringify(baseline.expectedTools),
      JSON.stringify(baseline.expectedExternalDomains),
      baseline.avgToolCallsPerTask,
      baseline.maxToolCallsPerTask,
      baseline.avgDurationMs,
      baseline.learningCount
    )
  }

  load(taskType: string): AgentBaseline | undefined {
    if (this.useFallback) {
      return this.fallbackMap.get(taskType)
    }
    
    const stmt = this.db.prepare('SELECT * FROM agent_baselines WHERE task_type = ?')
    const row = stmt.get(taskType)
    
    if (!row) return undefined
    
    return this.rowToBaseline(row)
  }

  loadAll(): AgentBaseline[] {
    if (this.useFallback) {
      return Array.from(this.fallbackMap.values())
    }
    
    const stmt = this.db.prepare('SELECT * FROM agent_baselines')
    const rows = stmt.all()
    
    return rows.map((row: any) => this.rowToBaseline(row))
  }

  private rowToBaseline(row: any): AgentBaseline {
    return {
      taskType: row.task_type,
      expectedTools: JSON.parse(row.expected_tools),
      expectedExternalDomains: JSON.parse(row.expected_external_domains),
      avgToolCallsPerTask: row.avg_tool_calls,
      maxToolCallsPerTask: row.max_tool_calls,
      avgDurationMs: row.avg_duration_ms,
      learningCount: row.learning_count
    }
  }
}

export default class RuntimeGovernanceMonitor {
  private config: Required<GovernanceConfig>
  private store: BaselineStore
  private baselines: Map<string, AgentBaseline> = new Map()

  constructor(config: GovernanceConfig) {
    this.config = {
      strictMode: config.strictMode ?? false,
      learningMode: config.learningMode ?? true,
      maxUnknownTools: config.maxUnknownTools ?? 2,
      maxExternalDomains: config.maxExternalDomains ?? 3,
      dbPath: config.dbPath ?? ':memory:'
    }
    
    this.store = new BaselineStore(this.config.dbPath)
    
    // Load existing baselines from store
    const storedBaselines = this.store.loadAll()
    for (const baseline of storedBaselines) {
      this.baselines.set(baseline.taskType, baseline)
    }
  }

  learn(taskType: string, trace: { toolCalls: Array<{tool: string}>, externalCalls: string[], durationMs: number }): void {
    const existing = this.baselines.get(taskType)
    
    if (!existing) {
      // Create new baseline
      const tools = [...new Set(trace.toolCalls.map(t => t.tool))]
      const domains = [...new Set(trace.externalCalls)]
      
      const newBaseline: AgentBaseline = {
        taskType,
        expectedTools: tools,
        expectedExternalDomains: domains,
        avgToolCallsPerTask: trace.toolCalls.length,
        maxToolCallsPerTask: trace.toolCalls.length,
        avgDurationMs: trace.durationMs,
        learningCount: 1
      }
      
      this.baselines.set(taskType, newBaseline)
      this.store.save(newBaseline)
    } else {
      // Update existing baseline with running averages
      const newCount = existing.learningCount + 1
      
      // Union of tools and domains
      const newTools = trace.toolCalls.map(t => t.tool)
      const allTools = [...new Set([...existing.expectedTools, ...newTools])]
      const allDomains = [...new Set([...existing.expectedExternalDomains, ...trace.externalCalls])]
      
      // Running average for tool calls: ((old_avg * n) + new_value) / (n + 1)
      const newAvgToolCalls = ((existing.avgToolCallsPerTask * existing.learningCount) + trace.toolCalls.length) / newCount
      
      // Update max tool calls
      const newMaxToolCalls = Math.max(existing.maxToolCallsPerTask, trace.toolCalls.length)
      
      // Running average for duration
      const newAvgDuration = ((existing.avgDurationMs * existing.learningCount) + trace.durationMs) / newCount
      
      const updated: AgentBaseline = {
        taskType,
        expectedTools: allTools,
        expectedExternalDomains: allDomains,
        avgToolCallsPerTask: newAvgToolCalls,
        maxToolCallsPerTask: newMaxToolCalls,
        avgDurationMs: newAvgDuration,
        learningCount: newCount
      }
      
      this.baselines.set(taskType, updated)
      this.store.save(updated)
    }
  }

  monitor(taskType: string, currentTrace: { toolCalls: Array<{tool: string}>, externalCalls: string[], durationMs: number }): GovernanceAlert[] {
    const alerts: GovernanceAlert[] = []
    const baseline = this.baselines.get(taskType)
    
    // Check: No baseline exists
    if (!baseline) {
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity: 'low',
        rule: 'NO_BASELINE',
        description: 'No baseline for task type, still learning',
        evidence: { taskType },
        timestamp: new Date()
      })
      return alerts
    }
    
    // Check: Baseline still forming
    if (baseline.learningCount < 5) {
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity: 'low',
        rule: 'BASELINE_FORMING',
        description: 'Baseline still forming',
        evidence: { learningCount: baseline.learningCount, minRequired: 5 },
        timestamp: new Date()
      })
    }
    
    // Skip violation checks if in learning mode
    if (this.config.learningMode) {
      return alerts
    }
    
    const currentTools = currentTrace.toolCalls.map(t => t.tool)
    
    // Check 1: Unknown tools
    const unknownTools = currentTools.filter(tool => !baseline.expectedTools.includes(tool))
    const uniqueUnknownTools = [...new Set(unknownTools)]
    
    if (uniqueUnknownTools.length > 0) {
      const severity: GovernanceAlert['severity'] = uniqueUnknownTools.length > this.config.maxUnknownTools ? 'high' : 'medium'
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity,
        rule: 'UNKNOWN_TOOLS',
        description: `Agent used ${uniqueUnknownTools.length} unknown tools: ${uniqueUnknownTools.join(', ')}`,
        evidence: { 
          unknownTools: uniqueUnknownTools, 
          expectedTools: baseline.expectedTools,
          actualTools: currentTools 
        },
        timestamp: new Date()
      })
    }
    
    // Check 2: Unknown external domains
    const unknownDomains = currentTrace.externalCalls.filter(domain => !baseline.expectedExternalDomains.includes(domain))
    const uniqueUnknownDomains = [...new Set(unknownDomains)]
    
    if (uniqueUnknownDomains.length > 0) {
      const severity: GovernanceAlert['severity'] = uniqueUnknownDomains.length > this.config.maxExternalDomains ? 'high' : 'medium'
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity,
        rule: 'UNKNOWN_DOMAINS',
        description: `Agent called ${uniqueUnknownDomains.length} unknown external domains: ${uniqueUnknownDomains.join(', ')}`,
        evidence: { 
          unknownDomains: uniqueUnknownDomains, 
          expectedDomains: baseline.expectedExternalDomains,
          actualCalls: currentTrace.externalCalls 
        },
        timestamp: new Date()
      })
    }
    
    // Check 3: Potential loop (tool call count > 1.5x max)
    const toolCallCount = currentTrace.toolCalls.length
    const loopThreshold = baseline.maxToolCallsPerTask * 1.5
    
    if (toolCallCount > loopThreshold) {
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity: 'critical',
        rule: 'TOOL_CALL_LOOP',
        description: `Tool call count (${toolCallCount}) exceeds 1.5x max baseline (${baseline.maxToolCallsPerTask})`,
        evidence: { 
          currentCount: toolCallCount, 
          maxBaseline: baseline.maxToolCallsPerTask,
          threshold: loopThreshold 
        },
        timestamp: new Date()
      })
    }
    
    // Check 4: Duration anomaly (> 3x average)
    const durationThreshold = baseline.avgDurationMs * 3
    
    if (currentTrace.durationMs > durationThreshold) {
      alerts.push({
        alertId: randomUUID(),
        taskType,
        severity: 'high',
        rule: 'DURATION_ANOMALY',
        description: `Duration (${currentTrace.durationMs}ms) exceeds 3x average (${Math.round(baseline.avgDurationMs)}ms)`,
        evidence: { 
          currentDuration: currentTrace.durationMs, 
          avgBaseline: baseline.avgDurationMs,
          threshold: durationThreshold 
        },
        timestamp: new Date()
      })
    }
    
    return alerts
  }

  enforce(alert: GovernanceAlert): EnforcementAction {
    if (alert.severity === 'critical') {
      return 'terminate'
    }
    
    if (alert.severity === 'high') {
      return this.config.strictMode ? 'terminate' : 'pause'
    }
    
    // medium or low
    return 'warn'
  }

  getBaseline(taskType: string): AgentBaseline | undefined {
    return this.baselines.get(taskType)
  }

  exportBaselines(): AgentBaseline[] {
    return Array.from(this.baselines.values())
  }

  importBaselines(baselines: AgentBaseline[]): void {
    for (const baseline of baselines) {
      this.baselines.set(baseline.taskType, baseline)
      this.store.save(baseline)
    }
  }
}
