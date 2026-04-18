
import type { Context, MiddlewareHandler, Next } from 'hono';
import { randomBytes } from 'node:crypto';

export interface ApiKeyConfig {
  keys: string[];
  headerName?: string;
  queryParam?: string;
  allowBearer?: boolean;
  onUnauthorized?: (c: Context) => Response | Promise<Response>;
}

export function apiKeyAuth(config: ApiKeyConfig): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const headerName = config.headerName || 'x-api-key';
    let key: string | undefined;

    // Check header
    key = c.req.header(headerName);

    // Check Bearer token if allowed
    if (!key && config.allowBearer) {
      const authHeader = c.req.header('Authorization');
      if (authHeader && authHeader.startsWith('Bearer ')) {
        key = authHeader.substring(7);
      }
    }

    // Check query param if configured
    if (!key && config.queryParam) {
      key = c.req.query(config.queryParam) || undefined;
    }

    // Validate key
    if (!key || !config.keys.includes(key)) {
      if (config.onUnauthorized) {
        return config.onUnauthorized(c);
      }
      return c.json(
        { error: 'Unauthorized', message: 'Valid API key required' },
        401
      );
    }

    // Set key in context and proceed
    c.set('apiKey', key);
    await next();
    return;
  };
}

export function fromEnv(): ApiKeyConfig {
  const envKeys = process.env.ARNIKO_API_KEYS;
  if (!envKeys) {
    console.warn('ARNIKO_API_KEYS environment variable not set');
    return { keys: [] };
  }
  const keys = envKeys.split(',').map(k => k.trim()).filter(k => k.length > 0);
  return { keys };
}

export function generateApiKey(): string {
  return randomBytes(32).toString('hex');
}

export class ApiKeyStore {
  private keys: Set<string>;

  constructor(initialKeys?: string[]) {
    this.keys = new Set(initialKeys || []);
  }

  add(key: string): void {
    this.keys.add(key);
  }

  remove(key: string): boolean {
    return this.keys.delete(key);
  }

  has(key: string): boolean {
    return this.keys.has(key);
  }

  list(): string[] {
    return Array.from(this.keys).map(key => {
      if (key.length <= 8) {
        return '****';
      }
      return key.substring(0, 4) + '...' + key.substring(key.length - 4);
    });
  }

  toMiddlewareHandler(options?: Partial<ApiKeyConfig>): MiddlewareHandler {
    return apiKeyAuth({
      ...options,
      keys: Array.from(this.keys)
    });
  }
}
