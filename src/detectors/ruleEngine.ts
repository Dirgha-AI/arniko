import * as fs from 'fs';
import * as path from 'path';

/**
 * Supported operators for rule conditions
 */
type Operator = 
  | 'contains' 
  | 'matches' 
  | 'equals' 
  | 'gt' 
  | 'lt' 
  | 'not_contains' 
  | 'starts_with' 
  | 'ends_with' 
  | 'length_gt' 
  | 'length_lt';

/**
 * Supported fields for evaluation context
 */
type Field = 'input' | 'output' | 'user_id' | 'model' | 'token_count';

/**
 * Severity levels for security rules
 */
type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Actions to take when rules match
 */
type Action = 'block' | 'warn' | 'log' | 'redact';

/**
 * Represents a single condition within a security rule
 */
interface RuleCondition {
  /** The field to evaluate against */
  field: Field;
  /** The comparison operator */
  operator: Operator;
  /** The value to compare against (string, number, or RegExp) */
  value: string | number | RegExp;
}

/**
 * Represents a security detection rule
 */
interface SecurityRule {
  /** Unique identifier for the rule */
  id: string;
  /** Human-readable name */
  name: string;
  /** Detailed description of what this rule detects */
  description: string;
  /** Severity level of violations */
  severity: Severity;
  /** Whether the rule is active */
  enabled: boolean;
  /** Array of conditions (all must match for rule to trigger) */
  conditions: RuleCondition[];
  /** Action to take when rule matches */
  action: Action;
  /** Optional metadata for extensibility */
  metadata?: Record<string, unknown>;
}

/**
 * Context object provided during rule evaluation
 */
interface EvaluationContext {
  /** Input text/prompt to evaluate */
  input?: string;
  /** Output text/response to evaluate */
  output?: string;
  /** User identifier */
  userId?: string;
  /** Model identifier */
  model?: string;
  /** Token count for rate limiting checks */
  tokenCount?: number;
}

/**
 * Result of evaluating a single rule
 */
interface EvaluationResult {
  /** The rule that was evaluated */
  rule: SecurityRule;
  /** Whether all conditions matched */
  matched: boolean;
  /** List of condition descriptions that matched */
  matchedConditions: string[];
}

/**
 * Custom YAML parser for rule documents
 * Handles the specific subset of YAML used by security rules
 */
class SimpleYAMLParser {
  /**
   * Parse YAML content into array of documents
   */
  static parse(content: string): any[] {
    const documents: any[] = [];
    // Split on document separator (---)
    const parts = content.split(/^---\s*$/m);
    
    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      
      try {
        const doc = this.parseDocument(trimmed);
        documents.push(doc);
      } catch (err) {
        console.error('Failed to parse YAML document:', err);
      }
    }
    
    return documents;
  }

  /**
   * Parse a single YAML document
   */
  private static parseDocument(content: string): any {
    const lines = content.split('\n');
    const result: any = {};
    let i = 0;
    
    while (i < lines.length) {
      const line = lines[i]!;
      const trimmed = line.trim();
      
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        i++;
        continue;
      }
      
      // Check if this is a top-level key
      const match = trimmed.match(/^(\w+):\s*(.*)$/);
      if (match) {
        const [, key = '', value] = match;
        
        if (value) {
          // Simple key-value pair
          result[key] = this.parseValue(value);
          i++;
        } else {
          // Check if next line is an array item
          if (i + 1 < lines.length && lines[i + 1]!.trim().startsWith('-')) {
            const { items, nextIndex } = this.parseArray(lines, i + 1);
            result[key] = items;
            i = nextIndex;
          } else {
            // Empty value or nested object (treat as empty object for now)
            result[key] = {};
            i++;
          }
        }
      } else {
        i++;
      }
    }
    
    return result;
  }

  /**
   * Parse an array of items (supports objects within arrays)
   */
  private static parseArray(lines: string[], startIndex: number): { items: any[], nextIndex: number } {
    const items: any[] = [];
    let i = startIndex;
    const baseIndent = this.getIndentLevel(lines[startIndex] ?? '');
    
    while (i < lines.length) {
      const line = lines[i]!;
      if (!line.trim()) {
        i++;
        continue;
      }
      
      const currentIndent = this.getIndentLevel(line);
      if (currentIndent < baseIndent) break;
      
      const trimmed = line.trim();
      if (trimmed.startsWith('-')) {
        const itemContent = trimmed.substring(1).trim();
        
        if (itemContent.includes(':')) {
          // Object in array - parse the object properties
          const obj: any = {};
          const firstColon = itemContent.indexOf(':');
          const firstKey = itemContent.substring(0, firstColon).trim();
          const firstValue = itemContent.substring(firstColon + 1).trim();
          
          if (firstValue) {
            obj[firstKey] = this.parseValue(firstValue);
          }
          
          i++;
          // Parse remaining properties of this object
          while (i < lines.length) {
            const nextLine = lines[i]!;
            if (!nextLine.trim()) {
              i++;
              continue;
            }
            
            const nextIndent = this.getIndentLevel(nextLine);
            if (nextIndent <= baseIndent) break;
            
            const nextTrimmed = nextLine.trim();
            const propMatch = nextTrimmed.match(/^(\w+):\s*(.*)$/);
            if (propMatch) {
              obj[propMatch[1] ?? ''] = this.parseValue(propMatch[2] ?? '');
              i++;
            } else {
              i++;
            }
          }
          
          items.push(obj);
        } else if (itemContent) {
          // Simple value in array
          items.push(this.parseValue(itemContent));
          i++;
        } else {
          // Empty array item marker, skip
          i++;
        }
      } else {
        break;
      }
    }
    
    return { items, nextIndex: i };
  }

  /**
   * Get indentation level (number of leading spaces)
   */
  private static getIndentLevel(line: string): number {
    let count = 0;
    for (const char of line) {
      if (char === ' ') count++;
      else if (char === '\t') count += 2; // Treat tab as 2 spaces
      else break;
    }
    return count;
  }

  /**
   * Parse a scalar value into appropriate type
   */
  private static parseValue(value: string): any {
    const trimmed = value.trim();
    
    // Boolean
    if (trimmed === 'true') return true;
    if (trimmed === 'false') return false;
    if (trimmed === 'null') return null;
    
    // Number
    if (/^-?\d+$/.test(trimmed)) return parseInt(trimmed, 10);
    if (/^-?\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);
    
    // String (remove quotes if present)
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
        (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
      return trimmed.slice(1, -1);
    }
    
    return trimmed;
  }

  /**
   * Serialize rules to YAML format
   */
  static stringify(rules: SecurityRule[]): string {
    const docs: string[] = [];
    
    for (const rule of rules) {
      let yaml = '---\n';
      yaml += `id: ${this.escape(rule.id)}\n`;
      yaml += `name: ${this.escape(rule.name)}\n`;
      yaml += `description: ${this.escape(rule.description)}\n`;
      yaml += `severity: ${rule.severity}\n`;
      yaml += `enabled: ${rule.enabled}\n`;
      
      if (rule.metadata && Object.keys(rule.metadata).length > 0) {
        yaml += `metadata:\n`;
        for (const [key, val] of Object.entries(rule.metadata)) {
          yaml += `  ${key}: ${this.escape(String(val))}\n`;
        }
      }
      
      yaml += 'conditions:\n';
      for (const cond of rule.conditions) {
        yaml += '  - field: ' + cond.field + '\n';
        yaml += '    operator: ' + cond.operator + '\n';
        // Handle RegExp serialization
        const val = cond.value instanceof RegExp ? cond.value.source : cond.value;
        yaml += '    value: ' + this.escape(String(val)) + '\n';
      }
      
      yaml += `action: ${rule.action}\n`;
      docs.push(yaml);
    }
    
    return docs.join('\n');
  }

  /**
   * Escape string for YAML if needed
   */
  private static escape(str: string): string {
    if (!str) return '""';
    // Check if needs quoting
    if (/[:\s#\[\]{}|>&*!?,]/.test(str) || str === 'true' || str === 'false') {
      // Use single quotes, escape single quotes by doubling them
      return "'" + str.replace(/'/g, "''") + "'";
    }
    return str;
  }
}

/**
 * RuleEngine for the Arniko security platform
 * Manages security rules with hot-reload capabilities
 */
export class RuleEngine {
  /** Map of rule ID to SecurityRule */
  rules: Map<string, SecurityRule>;
  
  /** Directory containing rule files */
  private rulesDir: string;
  
  /** File system watcher for hot-reload */
  private watcher?: fs.FSWatcher;

  /**
   * Create a new RuleEngine instance
   * @param rulesDir - Directory containing YAML rule files (default: './rules/')
   */
  constructor(rulesDir: string = './rules/') {
    this.rules = new Map();
    this.rulesDir = path.resolve(rulesDir);
  }

  /**
   * Load all YAML rule files from the rules directory
   * Parses files and populates the rules map
   */
  loadRules(): void {
    if (!fs.existsSync(this.rulesDir)) {
      console.warn(`Rules directory does not exist: ${this.rulesDir}`);
      return;
    }

    const files = fs.readdirSync(this.rulesDir).filter(f => 
      f.endsWith('.yaml') || f.endsWith('.yml')
    );

    let loadedCount = 0;
    
    for (const file of files) {
      const filePath = path.join(this.rulesDir, file);
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const documents = SimpleYAMLParser.parse(content);
        
        for (const doc of documents) {
          const rule = this.validateAndConvertRule(doc);
          if (rule) {
            this.rules.set(rule.id, rule);
            loadedCount++;
          }
        }
      } catch (err) {
        console.error(`Error loading rule file ${file}:`, err);
      }
    }
    
    console.log(`Loaded ${loadedCount} rules from ${files.length} files`);
  }

  /**
   * Validate and convert parsed YAML object to SecurityRule
   */
  private validateAndConvertRule(obj: any): SecurityRule | null {
    try {
      if (!obj.id || !obj.name || !obj.conditions) {
        console.warn('Invalid rule: missing required fields (id, name, conditions)');
        return null;
      }

      // Convert conditions
      const conditions: RuleCondition[] = [];
      if (Array.isArray(obj.conditions)) {
        for (const cond of obj.conditions) {
          let value: string | number | RegExp = cond.value;
          
          // Convert to RegExp if operator is matches
          if (cond.operator === 'matches' && typeof value === 'string') {
            value = new RegExp(value, 'i');
          } else if (typeof value === 'string' && /^-?\d+$/.test(value)) {
            value = parseInt(value, 10);
          }
          
          conditions.push({
            field: cond.field,
            operator: cond.operator,
            value: value
          });
        }
      }

      const rule: SecurityRule = {
        id: String(obj.id),
        name: String(obj.name),
        description: String(obj.description || ''),
        severity: obj.severity || 'medium',
        enabled: Boolean(obj.enabled !== false), // default true
        conditions,
        action: obj.action || 'log',
        metadata: obj.metadata || {}
      };

      // Validate enums
      const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low'];
      const validActions: Action[] = ['block', 'warn', 'log', 'redact'];
      const validFields: Field[] = ['input', 'output', 'user_id', 'model', 'token_count'];
      const validOperators: Operator[] = [
        'contains', 'matches', 'equals', 'gt', 'lt', 
        'not_contains', 'starts_with', 'ends_with', 'length_gt', 'length_lt'
      ];

      if (!validSeverities.includes(rule.severity)) {
        console.warn(`Invalid severity for rule ${rule.id}: ${rule.severity}`);
        rule.severity = 'medium';
      }

      if (!validActions.includes(rule.action)) {
        console.warn(`Invalid action for rule ${rule.id}: ${rule.action}`);
        rule.action = 'log';
      }

      // Validate conditions
      for (const cond of rule.conditions) {
        if (!validFields.includes(cond.field)) {
          console.warn(`Invalid field in rule ${rule.id}: ${cond.field}`);
        }
        if (!validOperators.includes(cond.operator)) {
          console.warn(`Invalid operator in rule ${rule.id}: ${cond.operator}`);
        }
      }

      return rule;
    } catch (err) {
      console.error('Error validating rule:', err);
      return null;
    }
  }

  /**
   * Add a rule at runtime
   * @param rule - The security rule to add
   */
  addRule(rule: SecurityRule): void {
    this.rules.set(rule.id, rule);
    console.log(`Added rule: ${rule.id}`);
  }

  /**
   * Remove a rule by ID
   * @param ruleId - The ID of the rule to remove
   */
  removeRule(ruleId: string): void {
    if (this.rules.has(ruleId)) {
      this.rules.delete(ruleId);
      console.log(`Removed rule: ${ruleId}`);
    } else {
      console.warn(`Rule not found: ${ruleId}`);
    }
  }

  /**
   * Evaluate all enabled rules against the provided context
   * @param context - The evaluation context containing input/output/user data
   * @returns Array of evaluation results with match status
   */
  evaluate(context: EvaluationContext): EvaluationResult[] {
    const results: EvaluationResult[] = [];

    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      const matchedConditions: string[] = [];
      let allMatch = true;

      for (const condition of rule.conditions) {
        const fieldValue = this.getFieldValue(context, condition.field);
        const matches = this.evaluateCondition(fieldValue, condition);

        if (matches) {
          matchedConditions.push(`${condition.field} ${condition.operator} ${condition.value}`);
        } else {
          allMatch = false;
        }
      }

      results.push({
        rule,
        matched: allMatch,
        matchedConditions
      });
    }

    return results;
  }

  /**
   * Get value from context based on field name
   */
  private getFieldValue(context: EvaluationContext, field: Field): any {
    switch (field) {
      case 'input': return context.input;
      case 'output': return context.output;
      case 'user_id': return context.userId;
      case 'model': return context.model;
      case 'token_count': return context.tokenCount;
      default: return undefined;
    }
  }

  /**
   * Evaluate a single condition against a value
   */
  private evaluateCondition(fieldValue: any, condition: RuleCondition): boolean {
    if (fieldValue === undefined || fieldValue === null) return false;

    const { operator, value } = condition;
    const strValue = String(fieldValue);
    const numValue = Number(fieldValue);

    switch (operator) {
      case 'contains':
        return strValue.includes(String(value));
      
      case 'not_contains':
        return !strValue.includes(String(value));
      
      case 'matches':
        if (value instanceof RegExp) {
          return value.test(strValue);
        }
        return new RegExp(String(value), 'i').test(strValue);
      
      case 'equals':
        return fieldValue === value || strValue === String(value);
      
      case 'gt':
        return numValue > Number(value);
      
      case 'lt':
        return numValue < Number(value);
      
      case 'starts_with':
        return strValue.startsWith(String(value));
      
      case 'ends_with':
        return strValue.endsWith(String(value));
      
      case 'length_gt':
        return strValue.length > Number(value);
      
      case 'length_lt':
        return strValue.length < Number(value);
      
      default:
        return false;
    }
  }

  /**
   * Export all rules as a YAML string
   * @returns YAML formatted string containing all rules
   */
  exportRules(): string {
    const rulesArray = Array.from(this.rules.values());
    return SimpleYAMLParser.stringify(rulesArray);
  }

  /**
   * Import rules from a YAML string
   * @param yaml - YAML string containing rule definitions
   */
  importRules(yaml: string): void {
    try {
      const documents = SimpleYAMLParser.parse(yaml);
      let count = 0;
      
      for (const doc of documents) {
        const rule = this.validateAndConvertRule(doc);
        if (rule) {
          this.rules.set(rule.id, rule);
          count++;
        }
      }
      
      console.log(`Imported ${count} rules`);
    } catch (err) {
      console.error('Error importing rules:', err);
      throw new Error('Failed to import rules: ' + (err as Error).message);
    }
  }

  /**
   * Watch the rules directory for changes and hot-reload
   * Automatically reloads rules when files are added, modified, or deleted
   */
  watchRules(): void {
    if (!fs.existsSync(this.rulesDir)) {
      console.error(`Cannot watch rules directory: ${this.rulesDir} does not exist`);
      return;
    }

    if (this.watcher) {
      this.watcher.close();
    }

    console.log(`Watching rules directory: ${this.rulesDir}`);

    this.watcher = fs.watch(this.rulesDir, (eventType, filename) => {
      if (!filename) return;
      
      // Only process YAML files
      if (!filename.endsWith('.yaml') && !filename.endsWith('.yml')) return;

      console.log(`Rule file ${eventType}: ${filename}`);
      
      // Debounce rapid changes
      setTimeout(() => {
        try {
          this.loadRules();
          console.log('Rules hot-reloaded successfully');
        } catch (err) {
          console.error('Error hot-reloading rules:', err);
        }
      }, 100);
    });

    // Handle errors
    this.watcher.on('error', (err) => {
      console.error('Watcher error:', err);
    });
  }

  /**
   * Stop watching the rules directory
   */
  unwatchRules(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = undefined;
      console.log('Stopped watching rules directory');
    }
  }
}

// Export types for consumers
export type { SecurityRule, RuleCondition, EvaluationContext, EvaluationResult, Operator, Field, Severity, Action };
