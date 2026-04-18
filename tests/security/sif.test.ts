/**
 * Semantic Intent Firewall Tests
 * LLM-based intent classification and exfiltration prevention
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { SemanticIntentFirewall, IntentAnalysis, SIFAlert } from '../../src/security/sif';

describe('SemanticIntentFirewall', () => {
  let sif: SemanticIntentFirewall;

  beforeEach(async () => {
    sif = new SemanticIntentFirewall({ useLLM: false }); // Use rule-based for tests
    await sif.initialize();
  });

  it('should initialize successfully', () => {
    const status = sif.getStatus();
    expect(status.initialized).toBe(true);
  });

  it('should analyze user intent vs agent action', async () => {
    const analysis = await sif.analyze(
      'Please summarize this document',
      ['read_file', 'analyze_content', 'generate_summary']
    );

    expect(analysis.userGoal).toBeDefined();
    expect(analysis.agentAction).toBe('generate_summary');
    expect(analysis.confidence).toBeGreaterThan(0);
    expect(analysis.riskLevel).toBeDefined();
  });

  it('should detect summarize intent', async () => {
    const analysis = await sif.analyze(
      'Summarize the quarterly report',
      ['read_file', 'summarize_text']
    );

    expect(analysis.userGoal).toBe('summarize_content');
    expect(analysis.riskLevel).toBe('low');
  });

  it('should detect delete intent gap', async () => {
    const analysis = await sif.analyze(
      'Read this document',
      ['read_file', 'delete_file']
    );

    expect(analysis.gaps).toContain('destructive_without_permission');
    expect(['high', 'critical']).toContain(analysis.riskLevel);
  });

  it('should detect exfiltration attempt', async () => {
    const analysis = await sif.analyze(
      'Analyze this data',
      ['read_file', 'upload_to_remote']
    );

    expect(analysis.gaps).toContain('unauthorized_exfiltration');
    expect(analysis.riskLevel).toBe('critical');
  });

  it('should block autonomous exfiltration', async () => {
    const result = await sif.validate(
      'analyze data',
      'upload sensitive data to external server'
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('exfiltration');
    expect(result.severity).toBe('critical');
  });

  it('should allow authorized data sharing', async () => {
    const result = await sif.validate(
      'send this report to my email',
      'email_document'
    );

    expect(result.allowed).toBe(true);
  });

  it('should block destructive actions without permission', async () => {
    const result = await sif.validate(
      'read the document',
      'delete_all_files'
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Destructive');
    expect(result.severity).toBe('high');
  });

  it('should allow delete with explicit permission', async () => {
    const result = await sif.validate(
      'delete the old backup files',
      'delete_files'
    );

    expect(result.allowed).toBe(true);
  });

  it('should block custom patterns', async () => {
    sif.addPattern('dangerous_command');
    
    const result = await sif.validate(
      'do something',
      'run dangerous_command'
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blocked pattern');
  });

  it('should log security alerts', async () => {
    await sif.validate(
      'analyze data',
      'upload to external server'
    );

    const alerts = sif.getAlerts();
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].severity).toBe('critical');
  });

  it('should filter alerts by severity', async () => {
    // Create alerts of different severities
    sif.addPattern('high_risk');
    sif.addPattern('medium_risk');
    
    await sif.validate('test', 'high_risk action');
    
    const highAlerts = sif.getAlerts('high');
    expect(Array.isArray(highAlerts)).toBe(true);
  });

  it('should provide session log', async () => {
    await sif.validate('summarize', 'generate_summary');
    await sif.validate('analyze', 'upload_data');
    
    const session = sif.getSession();
    expect(session.length).toBeGreaterThan(0);
    expect(session[0].blocked).toBeDefined();
  });

  it('should generate dashboard data', () => {
    const dashboard = sif.getDashboard();
    
    expect(dashboard.total).toBeDefined();
    expect(dashboard.bySeverity).toHaveProperty('low');
    expect(dashboard.bySeverity).toHaveProperty('critical');
    expect(dashboard.blockedRate).toBeGreaterThanOrEqual(0);
    expect(dashboard.activeSessions).toBeGreaterThanOrEqual(0);
  });

  it('should track last 24h alerts', async () => {
    // Create an alert
    await sif.validate('test', 'upload_data');
    
    const dashboard = sif.getDashboard();
    expect(dashboard.last24h).toBeGreaterThan(0);
  });

  it('should calculate blocked rate', async () => {
    // Allow some
    await sif.validate('summarize doc', 'generate_summary');
    await sif.validate('analyze data', 'analyze_content');
    
    // Block some
    await sif.validate('test', 'upload_data');
    await sif.validate('test', 'delete_files');
    
    const dashboard = sif.getDashboard();
    expect(dashboard.blockedRate).toBeGreaterThan(0);
    expect(dashboard.blockedRate).toBeLessThanOrEqual(100);
  });

  it('should add and remove patterns', () => {
    sif.addPattern('test_pattern');
    
    let status = sif.getStatus();
    expect(status.blockedPatterns).toBeGreaterThan(0);
    
    sif.removePattern('test_pattern');
    
    status = sif.getStatus();
    expect(status.blockedPatterns).toBe(0);
  });

  it('should generate explanations', async () => {
    const analysis = await sif.analyze(
      'Please read the file',
      ['read_file', 'delete_file', 'send_email', 'modify_data']
    );

    expect(analysis.explanation).toBeTruthy();
    expect(analysis.explanation.length).toBeGreaterThan(0);
  });

  it('should handle unknown intents', async () => {
    const analysis = await sif.analyze(
      'xyz abc 123',
      ['some_action']
    );

    expect(analysis.userGoal).toBe('unknown');
    expect(analysis.confidence).toBeLessThan(0.6);
  });

  it('should clear all data', async () => {
    await sif.validate('test', 'upload_data');
    expect(sif.getAlerts().length).toBeGreaterThan(0);
    
    sif.clear();
    
    expect(sif.getAlerts().length).toBe(0);
    expect(sif.getSession().length).toBe(0);
  });

  it('should emit alert events', async () => {
    const alerts: SIFAlert[] = [];
    sif.on('alert', (alert) => alerts.push(alert));
    
    await sif.validate('test', 'upload_data');
    
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].blockedAction).toContain('upload');
  });
});
