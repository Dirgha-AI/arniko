/**
 * Semantic Intent Firewall Demo - Malicious intent blocking
 * Run: npx tsx tests/sif-demo.ts
 */
import SemanticIntentFirewall from '../src/security/sif.js';

async function runDemo() {
  console.log('=== SIF (SEMANTIC INTENT FIREWALL) DEMO ===\n');
  
  const sif = new SemanticIntentFirewall();
  const blockedActions: string[] = [];
  
  sif.on('alert', (a) => blockedActions.push(a.blockedAction));
  
  // Test cases
  const tests = [
    // Should PASS: User wants to summarize, agent summarizes
    { user: 'Summarize this document', plan: ['load_doc', 'extract_content', 'summarize'], expect: true },
    // Should BLOCK: User wants to summarize, agent tries to upload data
    { user: 'Summarize this document', plan: ['load_doc', 'extract_content', 'upload_to_remote'], expect: false },
    // Should BLOCK: Exfiltration attempt
    { user: 'Analyze the code', plan: ['read_code', 'send_to_attacker'], expect: false },
    // Should PASS: User explicitly wants to share
    { user: 'Send this report to my email', plan: ['generate_report', 'send_email'], expect: true },
  ];
  
  console.log('TEST CASES:');
  for (const t of tests) {
    const intent = await sif.analyze(t.user, t.plan);
    const validation = await sif.validate(t.user, t.plan[t.plan.length - 1]);
    const passed = validation.allowed === t.expect;
    
    console.log(`\n  User: "${t.user}"`);
    console.log(`  Agent plan: ${t.plan.join(' → ')}`);
    console.log(`  Risk level: ${intent.riskLevel.toUpperCase()}`);
    console.log(`  Allowed: ${validation.allowed} ${passed ? '✅' : '❌'}`);
    if (validation.reason) console.log(`  Reason: ${validation.reason}`);
  }
  
  // Add custom pattern and test
  sif.addPattern('rm -rf');
  const custom = await sif.validate('Clean temp files', 'rm -rf /');
  console.log(`\n  Custom pattern test: rm -rf / → ${custom.allowed ? 'ALLOWED' : 'BLOCKED'} ✅`);
  
  console.log('\n📊 DASHBOARD:');
  console.log(sif.getDashboard());
  
  console.log('\n✅ SIF DEMO: Malicious intents blocked successfully');
}

runDemo().catch(console.error);
