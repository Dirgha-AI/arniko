
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { ScanTarget, ScanResult, ScanFinding, ScanStatus, ScanSeverity, ScanTool } from '../types/index.js';

export interface ModelAttestation {
  modelPath: string;
  sha256: string;
  size: number;
  attestedAt: Date;
  slsaLevel: 1 | 2 | 3 | 4;
  provenance: {
    builder: string;
    buildType: string;
    materials: string[];
    environment: Record<string, string>;
  };
  signature?: string;
}

export interface ModelSBOM {
  modelPath: string;
  format: 'spdx' | 'cyclonedx';
  components: Array<{
    name: string;
    version?: string;
    type: 'framework' | 'dataset' | 'base-model' | 'adapter' | 'unknown';
    license?: string;
    sha256?: string;
  }>;
  generatedAt: Date;
}

export interface SlsaConfig {
  trustedBuilders?: string[];
  requiredLevel?: 1 | 2 | 3 | 4;
  checkSignatures?: boolean;
  simulation?: boolean;
}

export class ModelProvenance {
  private config: SlsaConfig;

  constructor(config: SlsaConfig) {
    this.config = config;
  }

  async attest(modelPath: string): Promise<ModelAttestation> {
    const stats = await fs.stat(modelPath);
    if (!stats.isFile()) {
      throw new Error(`Path is not a file: ${modelPath}`);
    }

    const hash = createHash('sha256');
    const fileHandle = await fs.open(modelPath, 'r');
    const buffer = Buffer.alloc(8192);
    let readResult: { bytesRead: number } = { bytesRead: 0 };

    try {
      while ((readResult = await fileHandle.read(buffer, 0, 8192, null)).bytesRead > 0) {
        hash.update(buffer.subarray(0, readResult.bytesRead));
      }
    } finally {
      await fileHandle.close();
    }

    const sha256 = hash.digest('hex');
    const ext = path.extname(modelPath).toLowerCase();
    const format = ['.gguf', '.safetensors', '.pt', '.bin', '.onnx', '.mlmodel'].includes(ext)
      ? ext.slice(1)
      : 'unknown';

    const dir = path.dirname(modelPath);
    const configPath = path.join(dir, 'config.json');
    let provenance = {
      builder: 'unknown',
      buildType: 'unknown',
      materials: [] as string[],
      environment: {} as Record<string, string>
    };

    try {
      const configContent = await fs.readFile(configPath, 'utf-8');
      const configData = JSON.parse(configContent);

      provenance.builder = configData._name_or_path || configData.model_type || 'unknown';
      provenance.buildType = this.inferBuildType(configData);
      provenance.materials = this.extractMaterials(configData);
      provenance.environment = this.extractEnvironment(configData);
    } catch {
      // config.json not found or invalid
    }

    let slsaLevel: 1 | 2 | 3 | 4 = 1;

    if (provenance.builder !== 'unknown' || provenance.materials.length > 0) {
      slsaLevel = 2;
    }

    try {
      const sigPath = modelPath + '.sig';
      await fs.access(sigPath);
      slsaLevel = 3;
    } catch {
      // No signature file
    }

    if (provenance.environment.CUDA_VERSION && provenance.environment.PYTHON_VERSION) {
      slsaLevel = 4;
    }

    return {
      modelPath,
      sha256,
      size: stats.size,
      attestedAt: new Date(),
      slsaLevel,
      provenance,
      signature: slsaLevel >= 3 ? randomUUID() : undefined
    };
  }

  private inferBuildType(configData: any): string {
    if (configData._commit_hash) return 'pretrain';
    if (configData.adapter_config) return 'fine-tune';
    if (configData.rag_config) return 'rag-augmented';
    return 'unknown';
  }

  private extractMaterials(configData: any): string[] {
    const materials: string[] = [];
    if (configData.datasets) materials.push(...configData.datasets);
    if (configData.base_model) materials.push(configData.base_model);
    return materials;
  }

  private extractEnvironment(configData: any): Record<string, string> {
    const env: Record<string, string> = {};
    if (configData.torch_dtype) env.TORCH_DTYPE = configData.torch_dtype;
    if (configData.transformers_version) env.TRANSFORMERS_VERSION = configData.transformers_version;
    if (configData._name_or_path) env.MODEL_SOURCE = configData._name_or_path;
    return env;
  }

  async verify(modelPath: string, attestation: ModelAttestation): Promise<{ valid: boolean; issues: string[] }> {
    const issues: string[] = [];
    let valid = true;

    const hash = createHash('sha256');
    const fileHandle = await fs.open(modelPath, 'r');
    const buffer = Buffer.alloc(8192);
    let readResult2: { bytesRead: number } = { bytesRead: 0 };

    try {
      while ((readResult2 = await fileHandle.read(buffer, 0, 8192, null)).bytesRead > 0) {
        hash.update(buffer.subarray(0, readResult2.bytesRead));
      }
    } finally {
      await fileHandle.close();
    }

    const currentHash = hash.digest('hex');

    if (currentHash !== attestation.sha256) {
      valid = false;
      issues.push(`Hash mismatch: expected ${attestation.sha256}, got ${currentHash}`);
    }

    if (attestation.attestedAt > new Date()) {
      valid = false;
      issues.push('Attestation timestamp is in the future');
    }

    if (this.config.requiredLevel && attestation.slsaLevel < this.config.requiredLevel) {
      issues.push(`SLSA level ${attestation.slsaLevel} below required ${this.config.requiredLevel}`);
    }

    return { valid, issues };
  }

  async generateSBOM(modelPath: string, format: 'spdx' | 'cyclonedx' = 'spdx'): Promise<ModelSBOM> {
    const dir = path.dirname(modelPath);
    const components: ModelSBOM['components'] = [];

    try {
      const reqPath = path.join(dir, 'requirements.txt');
      const reqContent = await fs.readFile(reqPath, 'utf-8');
      const lines = reqContent.split('\n');
      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)([=<>!~]+)?(.*)?$/);
        if (match && match[1]) {
          components.push({
            name: match[1],
            version: match[3] || undefined,
            type: 'framework'
          });
        }
      }
    } catch {
      // requirements.txt not found
    }

    try {
      const envPath = path.join(dir, 'environment.yml');
      const envContent = await fs.readFile(envPath, 'utf-8');
      const lines = envContent.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*-\s*([a-zA-Z0-9_-]+)(=)?(.*)?$/);
        if (match && match[1]) {
          components.push({
            name: match[1],
            version: match[3] || undefined,
            type: 'framework'
          });
        }
      }
    } catch {
      // environment.yml not found
    }

    const configPath = path.join(dir, 'config.json');
    try {
      const configContent = await fs.readFile(configPath, 'utf-8');
      const configData = JSON.parse(configContent);

      if (configData.transformers_version) {
        components.push({
          name: 'transformers',
          version: configData.transformers_version,
          type: 'framework'
        });
      }

      if (configData.torch_dtype) {
        components.push({
          name: 'torch',
          type: 'framework'
        });
      }

      if (configData._name_or_path) {
        components.push({
          name: configData._name_or_path,
          type: 'base-model'
        });
      }
    } catch {
      // config.json not found
    }

    return {
      modelPath,
      format,
      components,
      generatedAt: new Date()
    };
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const scanId = randomUUID();
    const modelPath = target.identifier || (target.metadata?.modelPath as string);

    const makeFinding = (severity: any, message: string, meta?: any): ScanFinding => ({
      id: randomUUID(),
      tool: 'custom' as const,
      severity,
      title: message,
      description: message,
      cwe: 'CWE-494',
      owasp: 'AI-Supply-Chain',
      metadata: meta,
    });

    if (!modelPath) {
      const completedAt = new Date();
      return { scanId, status: 'failed' as const, tool: 'custom' as const, target, findings: [makeFinding('critical', 'No model path provided')], startedAt, completedAt, durationMs: 0 };
    }

    if (this.config.simulation) {
      const completedAt = new Date();
      return { scanId, status: 'completed' as const, tool: 'custom' as const, target, findings: [makeFinding('info', `SLSA attestation demo for ${modelPath}`, { slsaLevel: 3, builder: 'simulated-builder' })], startedAt, completedAt, durationMs: completedAt.getTime() - startedAt.getTime() };
    }

    try {
      const rawFindings: ScanFinding[] = [];
      const attestation = await this.attest(modelPath);

      if (target.metadata?.existingAttestation) {
        const verification = await this.verify(modelPath, target.metadata.existingAttestation as any);
        if (!verification.valid) {
          rawFindings.push(makeFinding('critical', 'Model integrity check failed', { issues: verification.issues }));
        }
      }

      if (attestation.slsaLevel < 2) {
        rawFindings.push(makeFinding('medium', 'No build provenance — SLSA Level 1 only', { currentLevel: attestation.slsaLevel }));
      }

      rawFindings.push(makeFinding('info', `Model attested at SLSA Level ${attestation.slsaLevel}`, { sha256: attestation.sha256 }));

      const hasCritical = rawFindings.some(f => f.severity === 'critical');
      const completedAt = new Date();
      return { scanId, status: hasCritical ? 'failed' as const : 'completed' as const, tool: 'custom' as const, target, findings: rawFindings, startedAt, completedAt, durationMs: completedAt.getTime() - startedAt.getTime(), metadata: { attestation } };
    } catch (error) {
      const completedAt = new Date();
      return { scanId, status: 'failed' as const, tool: 'custom' as const, target, findings: [makeFinding('critical', `Failed to attest model: ${error instanceof Error ? error.message : String(error)}`)], startedAt, completedAt, durationMs: completedAt.getTime() - startedAt.getTime(), error: error instanceof Error ? error.message : String(error) };
    }
  }
}
