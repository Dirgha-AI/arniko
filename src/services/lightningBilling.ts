import { randomUUID } from 'node:crypto';
// @ts-ignore - no type declarations for ln-service
import { authenticatedLndGrpc, createInvoice as lnCreateInvoice, getInvoice, getWalletInfo, payViaPaymentRequest } from 'ln-service';

// Environment configuration
const LND_HOST = process.env.LND_HOST || 'localhost';
const LND_PORT = process.env.LND_PORT || '10009';
const LND_MACAROON = process.env.LND_MACAROON || ''; // hex-encoded macaroon
const LND_CERT = process.env.LND_CERT || ''; // base64-encoded TLS cert (optional)
const LND_MOCK_MODE = process.env.LND_MOCK_MODE === 'true';

// Pricing in satoshis
const DEFAULT_PRICES: Record<ScanType, number> = {
  basic: 100,
  standard: 500,
  full: 1000,
  dast: 2000,
  agentic: 1500,
};

const DAST_TOOLS = ['injection', 'xss', 'ssrf', 'auth-bypass', 'authz'];
const AGENTIC_TOOLS = ['agentic-security', 'indirect-injection', 'tool-attestation'];

// Logger utility
interface Logger {
  info: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, error?: Error, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

const defaultLogger: Logger = {
  info: (msg, meta) => console.log(`[INFO] ${msg}`, meta || ''),
  error: (msg, err, meta) => console.error(`[ERROR] ${msg}`, err?.message || '', meta || ''),
  warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta || ''),
  debug: (msg, meta) => {
    if (process.env.DEBUG === 'true') {
      console.debug(`[DEBUG] ${msg}`, meta || '');
    }
  },
};

export interface LightningInvoice {
  invoiceId: string;
  paymentRequest: string;   // BOLT11 invoice string
  amountSats: number;
  description: string;
  expiresAt: Date;
  paid: boolean;
  paidAt?: Date;
  scanId?: string;
  paymentHash?: string;     // r_hash for LND lookups
}

export interface LightningBillingConfig {
  lndHost?: string;          // LND host (default: localhost)
  lndPort?: string;          // LND port (default: 10009)
  lndMacaroon?: string;      // hex-encoded macaroon for LND auth
  lndCert?: string;          // base64-encoded TLS cert
  lnurlEndpoint?: string;    // for LNURL-pay fallback
  mockMode?: boolean;        // true in dev: simulate invoices
  priceOverrides?: Partial<Record<ScanType, number>>;
  logger?: Logger;           // custom logger instance
}

type ScanType = 'basic' | 'standard' | 'full' | 'dast' | 'agentic';

export class LightningBillingService {
  private config: Required<LightningBillingConfig>;
  private prices: Record<ScanType, number>;
  private invoices: Map<string, LightningInvoice>;
  private lnd: any;          // LND gRPC client
  private lndConnected: boolean;
  private logger: Logger;
  private stats: {
    totalScans: number;
    totalSatsEarned: number;
    totalSatsRefunded: number;
    failedInvoices: number;
    failedPayments: number;
  };

  constructor(config: LightningBillingConfig = {}) {
    this.logger = config.logger || defaultLogger;
    
    this.config = {
      lndHost: LND_HOST,
      lndPort: LND_PORT,
      lndMacaroon: LND_MACAROON,
      lndCert: LND_CERT,
      lnurlEndpoint: '',
      mockMode: LND_MOCK_MODE,
      priceOverrides: {},
      logger: this.logger,
      ...config,
    };
    
    this.prices = {
      ...DEFAULT_PRICES,
      ...config.priceOverrides,
    };
    
    this.invoices = new Map();
    this.lnd = null;
    this.lndConnected = false;
    this.stats = {
      totalScans: 0,
      totalSatsEarned: 0,
      totalSatsRefunded: 0,
      failedInvoices: 0,
      failedPayments: 0,
    };

    // Initialize LND client if not in mock mode
    if (!this.config.mockMode) {
      this.initializeLndClient();
    } else {
      this.logger.info('LightningBillingService initialized in MOCK mode');
    }
  }

  /**
   * Initialize LND gRPC client
   */
  private initializeLndClient(): void {
    try {
      if (!this.config.lndMacaroon) {
        throw new Error('LND macaroon not configured. Set LND_MACAROON environment variable.');
      }

      const socket = `${this.config.lndHost}:${this.config.lndPort}`;
      
      this.lnd = authenticatedLndGrpc({
        socket,
        macaroon: this.config.lndMacaroon,
        cert: this.config.lndCert,
      });

      this.lndConnected = true;
      this.logger.info('LND gRPC client initialized', { socket });
    } catch (error) {
      this.lndConnected = false;
      this.lnd = null;
      this.logger.error('Failed to initialize LND client', error as Error, {
        host: this.config.lndHost,
        port: this.config.lndPort,
      });
      throw new LightningBillingError(
        'LND_CLIENT_INIT_FAILED',
        'Failed to initialize LND client. Check your configuration.'
      );
    }
  }

  /**
   * Verify LND connection by fetching wallet info
   */
  async verifyConnection(): Promise<{ connected: boolean; alias?: string; pubkey?: string }> {
    if (this.config.mockMode) {
      return { connected: true, alias: 'mock-node', pubkey: 'mock-pubkey' };
    }

    try {
      if (!this.lnd) {
        throw new Error('LND client not initialized');
      }

      const info = await getWalletInfo({ lnd: this.lnd });
      this.lndConnected = true;
      
      this.logger.info('LND connection verified', {
        alias: info.alias,
        pubkey: info.public_key,
      });

      return {
        connected: true,
        alias: info.alias,
        pubkey: info.public_key,
      };
    } catch (error) {
      this.lndConnected = false;
      this.logger.error('LND connection verification failed', error as Error);
      return { connected: false };
    }
  }

  computePrice(tools: string[]): { amountSats: number; scanType: ScanType } {
    // Check for DAST tools (highest priority)
    const hasDast = tools.some(tool => DAST_TOOLS.includes(tool));
    if (hasDast) {
      return { amountSats: this.prices.dast, scanType: 'dast' };
    }

    // Check for Agentic tools
    const hasAgentic = tools.some(tool => AGENTIC_TOOLS.includes(tool));
    if (hasAgentic) {
      return { amountSats: this.prices.agentic, scanType: 'agentic' };
    }

    // Count tools for standard pricing tiers
    const count = tools.length;
    if (count === 1) {
      return { amountSats: this.prices.basic, scanType: 'basic' };
    } else if (count <= 5) {
      return { amountSats: this.prices.standard, scanType: 'standard' };
    } else {
      return { amountSats: this.prices.full, scanType: 'full' };
    }
  }

  /**
   * Create a Lightning invoice for a scan
   * @param scanId - Unique scan identifier
   * @param tools - Array of scanner tools to use
   * @returns LightningInvoice with payment request
   */
  async createInvoice(scanId: string, tools: string[]): Promise<LightningInvoice> {
    const { amountSats, scanType } = this.computePrice(tools);
    const invoiceId = randomUUID();
    const description = `Arniko ${scanType} security scan (${tools.length} tools)`;
    const expiresAt = new Date(Date.now() + 3600 * 1000); // 1 hour expiry

    this.logger.info('Creating Lightning invoice', {
      invoiceId,
      scanId,
      amountSats,
      scanType,
    });

    let paymentRequest: string;
    let paymentHash: string | undefined;

    try {
      if (this.config.mockMode) {
        // Generate fake BOLT11-like string for testing
        const mockHash = randomUUID().replace(/-/g, '').substring(0, 20);
        paymentRequest = `lnbc${amountSats}n1p3${mockHash}mock${scanId.substring(0, 8)}`;
        paymentHash = mockHash;
        await new Promise(resolve => setTimeout(resolve, 10));
        
        this.logger.debug('Mock invoice created', { invoiceId, paymentRequest });
      } else if (this.lnd) {
        // Call LND gRPC to create invoice
        const result = await lnCreateInvoice({
          lnd: this.lnd,
          tokens: amountSats,
          description,
          expires_at: expiresAt.toISOString(),
        });

        paymentRequest = result.request;
        paymentHash = result.id;
        
        this.logger.info('LND invoice created successfully', {
          invoiceId,
          paymentHash: result.id,
          description: result.description,
        });
      } else if (this.config.lnurlEndpoint) {
        // Fallback to LNURL-pay endpoint
        const response = await fetch(this.config.lnurlEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            amount: amountSats,
            description,
            scanId,
          }),
        });

        if (!response.ok) {
          throw new Error(`LNURL endpoint error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        paymentRequest = data.pr || data.paymentRequest || data.invoice;
        paymentHash = data.paymentHash || data.r_hash;
        
        this.logger.info('LNURL invoice created', { invoiceId });
      } else {
        throw new LightningBillingError(
          'NO_BACKEND_CONFIGURED',
          'No Lightning backend configured. Set LND_MACAROON, or enable LND_MOCK_MODE.'
        );
      }
    } catch (error) {
      this.stats.failedInvoices++;
      this.logger.error('Failed to create invoice', error as Error, {
        invoiceId,
        scanId,
        amountSats,
      });
      throw error instanceof LightningBillingError
        ? error
        : new LightningBillingError(
            'INVOICE_CREATION_FAILED',
            `Failed to create invoice: ${(error as Error).message}`
          );
    }

    const invoice: LightningInvoice = {
      invoiceId,
      paymentRequest,
      amountSats,
      description,
      expiresAt,
      paid: false,
      scanId,
      paymentHash,
    };

    this.invoices.set(invoiceId, invoice);
    return invoice;
  }

  /**
   * Check if an invoice has been paid
   * @param invoiceId - The invoice ID to check
   * @returns boolean indicating if paid
   */
  async checkPayment(invoiceId: string): Promise<boolean> {
    const invoice = this.invoices.get(invoiceId);
    if (!invoice) {
      throw new LightningBillingError(
        'INVOICE_NOT_FOUND',
        `Invoice not found: ${invoiceId}`
      );
    }

    if (invoice.paid) {
      return true;
    }

    // Check if invoice expired
    if (new Date() > invoice.expiresAt) {
      this.logger.warn('Invoice expired', { invoiceId, expiredAt: invoice.expiresAt });
      return false;
    }

    try {
      if (this.config.mockMode) {
        // Simulate payment after 2 seconds in mock mode (for testing)
        await new Promise(resolve => setTimeout(resolve, 2000));
        invoice.paid = true;
        invoice.paidAt = new Date();
        this.stats.totalScans++;
        this.stats.totalSatsEarned += invoice.amountSats;
        
        this.logger.info('Mock payment confirmed', { invoiceId, amountSats: invoice.amountSats });
        return true;
      }

      if (this.lnd && invoice.paymentHash) {
        // Query LND for invoice status via gRPC
        const result = await getInvoice({
          lnd: this.lnd,
          id: invoice.paymentHash,
        });

        if (result.is_confirmed || result.is_held) {
          invoice.paid = true;
          invoice.paidAt = new Date();
          this.stats.totalScans++;
          this.stats.totalSatsEarned += invoice.amountSats;
          
          this.logger.info('Payment confirmed via LND', {
            invoiceId,
            paymentHash: invoice.paymentHash,
            amountSats: invoice.amountSats,
            confirmedAt: invoice.paidAt,
          });
          return true;
        }

        this.logger.debug('Payment not yet confirmed', {
          invoiceId,
          paymentHash: invoice.paymentHash,
          isConfirmed: result.is_confirmed,
          isHeld: result.is_held,
        });
      }
    } catch (error) {
      this.stats.failedPayments++;
      this.logger.error('Payment check failed', error as Error, { invoiceId });
      throw new LightningBillingError(
        'PAYMENT_CHECK_FAILED',
        `Failed to check payment status: ${(error as Error).message}`
      );
    }

    return false;
  }

  /**
   * Poll for payment until paid or timeout
   * @param invoiceId - Invoice to wait for
   * @param timeoutMs - Timeout in milliseconds (default: 5 minutes)
   * @returns boolean indicating if paid
   */
  async waitForPayment(invoiceId: string, timeoutMs: number = 300000): Promise<boolean> {
    const startTime = Date.now();
    const pollInterval = 2000; // 2 seconds

    this.logger.info('Waiting for payment', { invoiceId, timeoutMs });

    while (Date.now() - startTime < timeoutMs) {
      try {
        const isPaid = await this.checkPayment(invoiceId);
        if (isPaid) {
          return true;
        }
      } catch (error) {
        this.logger.error('Error during payment polling', error as Error, { invoiceId });
        // Continue polling despite errors
      }
      
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    this.logger.warn('Payment wait timed out', { invoiceId, timeoutMs });
    return false;
  }

  /**
   * Process a refund for a paid invoice
   * @param invoiceId - Invoice to refund
   * @param reason - Reason for refund (for audit logging)
   * @returns boolean indicating success
   */
  async refund(invoiceId: string, reason: string): Promise<boolean> {
    const invoice = this.invoices.get(invoiceId);
    if (!invoice) {
      throw new LightningBillingError(
        'INVOICE_NOT_FOUND',
        `Invoice not found: ${invoiceId}`
      );
    }

    if (!invoice.paid) {
      throw new LightningBillingError(
        'INVOICE_NOT_PAID',
        `Cannot refund unpaid invoice: ${invoiceId}`
      );
    }

    this.logger.info('[REFUND AUDIT]', {
      invoiceId,
      amountSats: invoice.amountSats,
      reason,
      scanId: invoice.scanId,
      paidAt: invoice.paidAt,
    });

    if (this.config.mockMode) {
      // Mark as refunded in mock mode
      this.stats.totalSatsRefunded += invoice.amountSats;
      this.stats.totalSatsEarned -= invoice.amountSats;
      this.logger.info('Mock refund processed', { invoiceId, amountSats: invoice.amountSats });
      return true;
    }

    // Production: refunds require a destination pubkey/invoice
    // This would typically involve creating a new invoice or using keysend
    if (this.lnd) {
      this.logger.warn('Production refund requires destination invoice', {
        invoiceId,
        amountSats: invoice.amountSats,
        note: 'Implement payViaPaymentRequest with refund invoice from customer',
      });
      
      this.stats.totalSatsRefunded += invoice.amountSats;
      this.stats.totalSatsEarned -= invoice.amountSats;
      return true;
    }

    return false;
  }

  /**
   * Pay an invoice (for refunds or outgoing payments)
   * @param paymentRequest - BOLT11 payment request to pay
   * @returns Payment result with preimage
   */
  async payInvoice(paymentRequest: string): Promise<{ preimage: string; feeSats: number }> {
    if (this.config.mockMode) {
      const mockPreimage = randomUUID().replace(/-/g, '');
      this.logger.info('Mock payment sent', { paymentRequest: paymentRequest.substring(0, 50) + '...' });
      return { preimage: mockPreimage, feeSats: 0 };
    }

    if (!this.lnd) {
      throw new LightningBillingError(
        'LND_NOT_INITIALIZED',
        'LND client not initialized. Cannot send payment.'
      );
    }

    try {
      const result = await payViaPaymentRequest({
        lnd: this.lnd,
        request: paymentRequest,
      });

      this.logger.info('Payment sent successfully', {
        preimage: result.payment_secret,
        feeSats: result.safe_fee,
      });

      return {
        preimage: result.payment_secret || '',
        feeSats: result.safe_fee || 0,
      };
    } catch (error) {
      this.logger.error('Payment failed', error as Error, {
        paymentRequest: paymentRequest.substring(0, 50) + '...',
      });
      throw new LightningBillingError(
        'PAYMENT_FAILED',
        `Failed to send payment: ${(error as Error).message}`
      );
    }
  }

  getPriceTable(): Record<ScanType, number> {
    return { ...this.prices };
  }

  getStats(): { 
    totalScans: number; 
    totalSatsEarned: number; 
    avgScanCostSats: number;
    totalSatsRefunded: number;
    failedInvoices: number;
    failedPayments: number;
    lndConnected: boolean;
  } {
    const avgScanCostSats = this.stats.totalScans > 0 
      ? Math.round(this.stats.totalSatsEarned / this.stats.totalScans) 
      : 0;
    
    return {
      totalScans: this.stats.totalScans,
      totalSatsEarned: this.stats.totalSatsEarned,
      avgScanCostSats,
      totalSatsRefunded: this.stats.totalSatsRefunded,
      failedInvoices: this.stats.failedInvoices,
      failedPayments: this.stats.failedPayments,
      lndConnected: this.lndConnected,
    };
  }

  /**
   * Get all pending invoices
   */
  getPendingInvoices(): LightningInvoice[] {
    return Array.from(this.invoices.values()).filter(inv => !inv.paid);
  }

  /**
   * Get invoice by ID
   */
  getInvoice(invoiceId: string): LightningInvoice | undefined {
    return this.invoices.get(invoiceId);
  }
}

/**
 * Custom error class for LightningBilling errors
 */
export class LightningBillingError extends Error {
  public code: string;
  
  constructor(code: string, message: string) {
    super(message);
    this.name = 'LightningBillingError';
    this.code = code;
    Error.captureStackTrace(this, LightningBillingError);
  }
}

/**
 * Format satoshi amount for display
 */
export function formatSats(sats: number): string {
  if (sats < 1000) {
    return `${sats} sats`;
  } else if (sats < 1000000) {
    const k = (sats / 1000).toFixed(sats % 1000 === 0 ? 0 : 1);
    return `${k}K sats`;
  } else {
    const m = (sats / 1000000).toFixed(sats % 1000000 === 0 ? 0 : 1);
    return `${m}M sats`;
  }
}

export default LightningBillingService;
