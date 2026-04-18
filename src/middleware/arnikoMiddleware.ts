/**
 * Arniko Hono Middleware
 *
 * Wraps @dirgha/security-shield into a Hono middleware.
 * Drop-in protection for any Hono route.
 *
 * Usage:
 *   import { arnikoMiddleware } from '@dirgha/arniko/middleware';
 *   app.use('/api/llm/*', arnikoMiddleware());
 */

import type { Context, MiddlewareHandler, Next } from 'hono';
// @ts-ignore - optional peer dependency
import { SecurityShield, type ShieldConfig } from '@dirgha/security-shield';

interface ArnikoMiddlewareOptions extends Partial<ShieldConfig> {
  getUserId?: (c: Context) => string;
  onBlocked?: (c: Context, reason: string) => void | Promise<void>;
  onRedacted?: (types: string[]) => void | Promise<void>;
}

export function arnikoMiddleware(options: ArnikoMiddlewareOptions = {}): MiddlewareHandler {
  const shield = new SecurityShield(options);

  const getUserId = options.getUserId ?? ((c: Context) => {
    // Try common header patterns
    const auth = c.req.header('x-user-id')
      || c.req.header('authorization')?.replace('Bearer ', '').slice(0, 20)
      || 'anonymous';
    return auth;
  });

  return async (c: Context, next: Next) => {
    const userId = getUserId(c);

    // --- Input check ---
    let input: string | undefined;

    if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
      try {
        const body = await c.req.json().catch(() => null);
        input = typeof body?.prompt === 'string' ? body.prompt
          : typeof body?.message === 'string' ? body.message
          : typeof body?.content === 'string' ? body.content
          : JSON.stringify(body);
      } catch {
        // Non-JSON body — skip input check
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
          403,
        );
      }

      // Store sanitized input for downstream handlers
      c.set('sanitizedInput', check.sanitizedInput);
      c.set('quotaRemaining', check.quotaRemaining);
    }

    // --- Run downstream ---
    await next();

    // --- Output filter ---
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

        // Replace response with filtered output
        c.res = new Response(filtered.output, {
          status: c.res.status,
          headers: c.res.headers,
        });
      } catch {
        // If output filtering fails, pass through unchanged (fail open)
      }
    }
    return;
  };
}

export { SecurityShield };
