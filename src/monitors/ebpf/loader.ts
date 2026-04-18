
import { promises as fs } from 'fs';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';

export interface EbpfConfig {
  enabled: boolean;
  tracePids: number[];
  allowedSyscalls?: string[];
  alertThreshold?: number;
}

export interface SyscallEvent {
  pid: number;
  syscall: string;
  args: string[];
  timestamp: Date;
  returnCode: number;
}

export class EbpfLoader {
  private config: EbpfConfig;
  private childProcesses: Map<number, ChildProcess>;
  private tempDir: string;

  constructor(config: EbpfConfig) {
    this.config = config;
    this.childProcesses = new Map();
    this.tempDir = '/tmp';
  }

  async isAvailable(): Promise<boolean> {
    try {
      await fs.access('/sys/kernel/btf/vmlinux');
      
      if (process.platform !== 'linux') {
        console.warn('eBPF not available: not running on Linux');
        return false;
      }
      
      const hasCapBpf = process.getuid && process.getuid() === 0;
      if (!hasCapBpf) {
        console.warn('eBPF not available: process lacks CAP_BPF capability (requires root)');
        return false;
      }
      
      return true;
    } catch (error) {
      console.warn('eBPF not available: BTF vmlinux not accessible or insufficient permissions');
      return false;
    }
  }

  async attach(pid: number): Promise<boolean> {
    const available = await this.isAvailable();
    
    if (!available) {
      console.warn(`eBPF not available for PID ${pid}, falling back to strace monitoring`);
      
      const logFile = path.join(this.tempDir, `arniko-trace-${pid}.log`);
      
      try {
        const child = spawn('strace', [
          '-p', pid.toString(),
          '-e', 'trace=all',
          '-o', logFile,
          '-f',
          '-tt',
          '-T',
          '-y'
        ], {
          detached: true,
          stdio: 'ignore'
        });
        
        child.on('error', (err) => {
          console.error(`Failed to start strace for PID ${pid}:`, err);
          this.childProcesses.delete(pid);
        });
        
        child.on('exit', (code) => {
          if (code !== 0 && code !== null) {
            console.warn(`strace for PID ${pid} exited with code ${code}`);
          }
          this.childProcesses.delete(pid);
        });
        
        this.childProcesses.set(pid, child);
        return true;
      } catch (error) {
        console.error(`Failed to attach strace to PID ${pid}:`, error);
        return false;
      }
    }
    
    console.log(`eBPF program attached to PID ${pid} (simulated)`);
    return true;
  }

  async detach(pid: number): Promise<void> {
    const child = this.childProcesses.get(pid);
    if (child) {
      try {
        process.kill(-(child.pid ?? 0), 'SIGTERM');
      } catch (error) {
        // Process might already be dead
      }
      this.childProcesses.delete(pid);
    }
    
    const logFile = path.join(this.tempDir, `arniko-trace-${pid}.log`);
    try {
      await fs.unlink(logFile);
    } catch (error) {
      // File might not exist
    }
  }

  async readEvents(pid: number, sinceMs?: number): Promise<SyscallEvent[]> {
    const logFile = path.join(this.tempDir, `arniko-trace-${pid}.log`);
    const events: SyscallEvent[] = [];
    const cutoffTime = sinceMs ? new Date(Date.now() - sinceMs) : null;
    
    try {
      const content = await fs.readFile(logFile, 'utf-8');
      const lines = content.split('\n');
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        const pidMatch = line.match(/^\[pid\s+(\d+)\]\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)\s*/);
        const noPidMatch = line.match(/^(\d{2}:\d{2}:\d{2}\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)\s*/);
        
        let parsedPid = pid;
        let timestamp: Date;
        let syscall: string;
        let args: string[];
        let returnCode: number;
        
        if (pidMatch) {
          parsedPid = parseInt(pidMatch[1] ?? '0', 10);
          const timeStr = pidMatch[2] ?? '';
          syscall = pidMatch[3] ?? '';
          const argsStr = pidMatch[4] ?? '';
          const retStr = pidMatch[5] ?? '';

          const [h, m, s] = timeStr.split(':').map(Number);
          const today = new Date();
          timestamp = new Date(today.getFullYear(), today.getMonth(), today.getDate(), h, m, s);

          args = this.parseArgs(argsStr);
          returnCode = retStr === '?' ? -1 : parseInt(retStr, 10);
        } else if (noPidMatch) {
          const timeStr = noPidMatch[1] ?? '';
          syscall = noPidMatch[2] ?? '';
          const argsStr = noPidMatch[3] ?? '';
          const retStr = noPidMatch[4] ?? '';

          const [h, m, s] = timeStr.split(':').map(Number);
          const today = new Date();
          timestamp = new Date(today.getFullYear(), today.getMonth(), today.getDate(), h, m, s);

          args = this.parseArgs(argsStr);
          returnCode = retStr === '?' ? -1 : parseInt(retStr, 10);
        } else {
          continue;
        }
        
        if (cutoffTime && timestamp < cutoffTime) {
          continue;
        }
        
        events.push({
          pid: parsedPid,
          syscall,
          args,
          timestamp,
          returnCode
        });
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error(`Error reading trace log for PID ${pid}:`, error);
      }
    }
    
    return events;
  }

  private parseArgs(argsStr: string): string[] {
    const args: string[] = [];
    let current = '';
    let inQuotes = false;
    let quoteChar = '';
    let depth = 0;
    
    for (let i = 0; i < argsStr.length; i++) {
      const char = argsStr[i];
      
      if (!inQuotes && (char === '"' || char === "'")) {
        inQuotes = true;
        quoteChar = char;
        continue;
      }
      
      if (inQuotes && char === quoteChar) {
        inQuotes = false;
        args.push(current);
        current = '';
        continue;
      }
      
      if (!inQuotes && char === '(') {
        depth++;
        current += char;
        continue;
      }
      
      if (!inQuotes && char === ')') {
        depth--;
        current += char;
        continue;
      }
      
      if (!inQuotes && char === ',' && depth === 0) {
        if (current.trim()) {
          args.push(current.trim());
        }
        current = '';
        continue;
      }
      
      current += char;
    }
    
    if (current.trim()) {
      args.push(current.trim());
    }
    
    return args;
  }

  async stop(): Promise<void> {
    const pids = Array.from(this.childProcesses.keys());
    await Promise.all(pids.map(pid => this.detach(pid)));
    
    try {
      const files = await fs.readdir(this.tempDir);
      const traceFiles = files.filter(f => f.startsWith('arniko-trace-'));
      await Promise.all(traceFiles.map(f => 
        fs.unlink(path.join(this.tempDir, f)).catch(() => {})
      ));
    } catch (error) {
      // Ignore cleanup errors
    }
  }
}
