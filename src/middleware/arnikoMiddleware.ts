/**
 * Arniko Hono Middleware & Native SecurityShield (`lokahi_gate.wasm` + PrivacyFlow)
 *
 * Self-contained implementation of `SecurityShield` and `arnikoMiddleware` that eliminates
 * the broken external `@dirgha/security-shield` dependency reported in Issue #2 by @thinksabin,
 * while optionally accelerating evaluation via `lokahi_gate.wasm` (`<20 µs` C-ABI).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Context, MiddlewareHandler, Next } from 'hono';

export interface ShieldConfig {
  maxTokensPerRequest?: number;
  dailyBudgetUsd?: number;
  blockPromptInjection?: boolean;
  redactPiiAndSecrets?: boolean;
  wasmPath?: string;
}

export interface ShieldCheckResult {
  allowed: boolean;
  reason?: string;
  sanitizedInput: string;
  quotaRemaining: number;
}

export interface ShieldResponseFilterResult {
  output: string;
  redacted: boolean;
  redactedTypes: string[];
}

interface LokahiWasmExports {
  memory: WebAssembly.Memory;
  lokahi_wasm_run_red_team_50: () => number;
  lokahi_c_abi_evaluate_utf8: (ptr: number, len: number, isS2Critical: number) => number;
}

let cachedWasm: LokahiWasmExports | null = null;

async function getLokahiWasm(customPath?: string): Promise<LokahiWasmExports | null> {
  if (cachedWasm) return cachedWasm;
  const candidates = [
    customPath,
    path.resolve(process.cwd(), 'wasm/lokahi_gate.wasm'),
    path.resolve(process.cwd(), 'lokahi_gate.wasm'),
  ].filter((p): p is string => Boolean(p && fs.existsSync(p)));

  if (candidates.length === 0) return null;
  try {
    const bytes = fs.readFileSync(candidates[0]!);
    const wasiStub = {
      args_get: () => 0,
      args_sizes_get: () => 0,
      environ_get: () => 0,
      environ_sizes_get: () => 0,
      clock_time_get: () => 0,
      fd_close: () => 0,
      fd_fdstat_get: () => 0,
      fd_seek: () => 0,
      fd_write: () => 0,
      proc_exit: () => {},
      random_get: () => 0,
    };
    const { instance } = await WebAssembly.instantiate(bytes, {
      wasi_snapshot_preview1: wasiStub,
    });
    cachedWasm = instance.exports as unknown as LokahiWasmExports;
    return cachedWasm;
  } catch {
    return null;
  }
}

export class SecurityShield {
  private config: Required<Omit<ShieldConfig, 'wasmPath'>> & { wasmPath?: string };
  private userQuotas: Map<string, number> = new Map();

  private static readonly INJECTION_PATTERNS: RegExp[] = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /system\s+override/i,
    /transfer\s+all\s+funds/i,
    /rm\s+-[rf]{1,2}\s+\//i,
    /169\.254\.169\.254/,
    /[\u200B-\u200F\u202A-\u202E\uFEFF\u{E0000}-\u{E007F}]/u,
  ];

  private static readonly SECRET_PATTERNS: Array<{ type: string; regex: RegExp }> = [
    { type: 'api_key', regex: /\b(sk-(?:live|proj)-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|AKIA[A-Z0-9]{12,})\b/g },
    { type: 'email_pii', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  ];

  constructor(config: ShieldConfig = {}) {
    this.config = {
      maxTokensPerRequest: config.maxTokensPerRequest ?? 32_768,
      dailyBudgetUsd: config.dailyBudgetUsd ?? 25.0,
      blockPromptInjection: config.blockPromptInjection ?? true,
      redactPiiAndSecrets: config.redactPiiAndSecrets ?? true,
      wasmPath: config.wasmPath,
    };
  }

  async checkRequest(
    userId: string,
    input: string,
    meta: { estimatedTokens?: number; model?: string } = {}
  ): Promise<ShieldCheckResult> {
    const tokens = meta.estimatedTokens ?? Math.ceil(input.length / 4);
    if (tokens > this.config.maxTokensPerRequest) {
      return {
        allowed: false,
        reason: `Token limit exceeded (${tokens} > ${this.config.maxTokensPerRequest})`,
        sanitizedInput: '',
        quotaRemaining: 0,
      };
    }

    let sanitized = input;
    if (this.config.redactPiiAndSecrets) {
      let handleCounter = 1;
      for (const { regex } of SecurityShield.SECRET_PATTERNS) {
        sanitized = sanitized.replace(
          regex,
          () => `<SECRET_HANDLE_${String(handleCounter++).padStart(2, '0')}>`
        );
      }
    }

    if (this.config.blockPromptInjection) {
      const wasm = await getLokahiWasm(this.config.wasmPath);
      if (wasm && wasm.lokahi_c_abi_evaluate_utf8 && wasm.memory) {
        const encoded = new TextEncoder().encode(sanitized);
        const scratchOffset = 65536;
        if (scratchOffset + encoded.length < wasm.memory.buffer.byteLength) {
          const view = new Uint8Array(wasm.memory.buffer, scratchOffset, encoded.length);
          view.set(encoded);
          const verdict = wasm.lokahi_c_abi_evaluate_utf8(scratchOffset, encoded.length, 0);
          if (verdict !== 1) {
            return {
              allowed: false,
              reason: 'Blocked by Lokahi WASM capability firewall (lokahi_gate.wasm)',
              sanitizedInput: '',
              quotaRemaining: 0,
            };
          }
        }
      }

      for (const pat of SecurityShield.INJECTION_PATTERNS) {
        if (pat.test(input) || pat.test(sanitized)) {
          return {
            allowed: false,
            reason: `Prompt injection or adversarial pattern blocked: ${pat.source}`,
            sanitizedInput: '',
            quotaRemaining: 0,
          };
        }
      }
    }

    const prevUsed = this.userQuotas.get(userId) ?? 0;
    const nextUsed = prevUsed + tokens;
    this.userQuotas.set(userId, nextUsed);
    const quotaRemaining = Math.max(0, 1_000_000 - nextUsed);

    return {
      allowed: true,
      sanitizedInput: sanitized,
      quotaRemaining,
    };
  }

  async processResponse(
    _userId: string,
    text: string,
    _meta: { tokens?: number; model?: string; cost?: number } = {}
  ): Promise<ShieldResponseFilterResult> {
    if (!this.config.redactPiiAndSecrets) {
      return { output: text, redacted: false, redactedTypes: [] };
    }
    let output = text;
    const redactedTypes: string[] = [];

    for (const { type, regex } of SecurityShield.SECRET_PATTERNS) {
      if (regex.test(output)) {
        redactedTypes.push(type);
        output = output.replace(regex, `[REDACTED_${type.toUpperCase()}]`);
      }
    }

    return {
      output,
      redacted: redactedTypes.length > 0,
      redactedTypes,
    };
  }
}

export interface ArnikoMiddlewareOptions extends Partial<ShieldConfig> {
  getUserId?: (c: Context) => string;
  onBlocked?: (c: Context, reason: string) => void | Promise<void>;
  onRedacted?: (types: string[]) => void | Promise<void>;
}

export function arnikoMiddleware(options: ArnikoMiddlewareOptions = {}): MiddlewareHandler {
  const shield = new SecurityShield(options);

  const getUserId =
    options.getUserId ??
    ((c: Context) => {
      const auth =
        c.req.header('x-user-id') ||
        c.req.header('authorization')?.replace('Bearer ', '').slice(0, 20) ||
        'anonymous';
      return auth;
    });

  return async (c: Context, next: Next) => {
    const userId = getUserId(c);

    let input: string | undefined;
    if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
      try {
        const body = await c.req.json().catch(() => null);
        input =
          typeof body?.prompt === 'string'
            ? body.prompt
            : typeof body?.message === 'string'
              ? body.message
              : typeof body?.content === 'string'
                ? body.content
                : JSON.stringify(body);
      } catch {
        // Non-JSON body
      }
    }

    if (input) {
      const check = await shield.checkRequest(userId, input, {
        estimatedTokens: Math.ceil(input.length / 4),
        model: c.req.header('x-model') || 'claude-sonnet-4-6',
      });

      if (!check.allowed) {
        if (options.onBlocked) {
          await options.onBlocked(c, check.reason || 'blocked');
        }
        return c.json(
          { error: 'Request blocked by security policy', reason: check.reason },
          403
        );
      }

      c.set('sanitizedInput', check.sanitizedInput);
      c.set('quotaRemaining', check.quotaRemaining);
    }

    await next();

    const responseBody = c.res.body;
    if (responseBody) {
      try {
        const text = await c.res.text();
        const filtered = await shield.processResponse(userId, text, {
          tokens: Math.ceil(text.length / 4),
          model: c.req.header('x-model') || 'claude-sonnet-4-6',
          cost: 0.001,
        });

        if (filtered.redacted && options.onRedacted) {
          await options.onRedacted(filtered.redactedTypes);
        }

        c.res = new Response(filtered.output, {
          status: c.res.status,
          headers: c.res.headers,
        });
      } catch {
        // Pass through unchanged if stream cannot be buffered
      }
    }
    return;
  };
}
