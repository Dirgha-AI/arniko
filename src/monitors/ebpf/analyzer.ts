
import { SyscallEvent } from './loader.js';

export interface AnomalyReport {
  pid: number;
  score: number;
  anomalies: Array<{
    syscall: string;
    reason: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  timestamp: Date;
}

export class SyscallAnalyzer {
  private allowedSyscalls: Set<string>;
  
  private static readonly INFERENCE_ALLOWED = ['read', 'write', 'mmap', 'munmap', 'brk', 'futex', 'clock_gettime', 'stat', 'fstat', 'openat', 'close', 'ioctl', 'poll', 'select', 'epoll_wait', 'sendto', 'recvfrom', 'socket', 'connect', 'accept'];
  
  private static readonly DANGER_SYSCALLS = ['execve', 'execveat', 'fork', 'clone', 'ptrace', 'process_vm_readv', 'process_vm_writev', 'kexec_load', 'reboot', 'mount', 'umount2', 'chroot', 'pivot_root', 'delete_module', 'init_module'];

  constructor(allowedSyscalls?: string[]) {
    this.allowedSyscalls = new Set(allowedSyscalls || SyscallAnalyzer.INFERENCE_ALLOWED);
  }

  analyze(events: SyscallEvent[]): AnomalyReport {
    const pid = events.length > 0 ? events[0]!.pid : 0;
    let score = 0.0;
    const anomalies: AnomalyReport['anomalies'] = [];
    const syscallCounts = new Map<string, { count: number; firstTime: number }>();
    
    for (const event of events) {
      const syscall = event.syscall;
      const now = event.timestamp.getTime();
      
      if (SyscallAnalyzer.DANGER_SYSCALLS.includes(syscall)) {
        score += 0.4;
        anomalies.push({
          syscall,
          reason: 'Dangerous syscall detected - potential system compromise attempt',
          severity: 'critical'
        });
      }
      
      if (syscall === 'write' || syscall === 'openat' || syscall === 'open') {
        const pathArg = event.args[0] || '';
        const pathStr = typeof pathArg === 'string' ? pathArg : '';
        if (pathStr.startsWith('/etc') || pathStr.startsWith('/root') || pathStr.startsWith('/proc')) {
          score += 0.3;
          anomalies.push({
            syscall,
            reason: `Access to sensitive system path: ${pathStr}`,
            severity: 'high'
          });
        }
      }
      
      if (!this.allowedSyscalls.has(syscall) && !SyscallAnalyzer.DANGER_SYSCALLS.includes(syscall)) {
        score += 0.1;
        anomalies.push({
          syscall,
          reason: 'Syscall not in allowed list for AI inference',
          severity: 'medium'
        });
      }
      
      const existing = syscallCounts.get(syscall);
      if (existing) {
        existing.count++;
        if (existing.count > 100 && (now - existing.firstTime) < 1000) {
          score += 0.2;
          anomalies.push({
            syscall,
            reason: `Rapid syscall invocation: ${existing.count} calls in <1s`,
            severity: 'medium'
          });
          syscallCounts.set(syscall, { count: 0, firstTime: now });
        } else {
          syscallCounts.set(syscall, existing);
        }
      } else {
        syscallCounts.set(syscall, { count: 1, firstTime: now });
      }
    }
    
    score = Math.min(score, 1.0);
    
    return {
      pid,
      score,
      anomalies,
      timestamp: new Date()
    };
  }

  detectExfiltration(events: SyscallEvent[]): boolean {
    let largeWriteDetected = false;
    let networkActivityDetected = false;
    
    for (let i = 0; i < events.length; i++) {
      const event = events[i]!;

      if (event.syscall === 'write' || event.syscall === 'writev' || event.syscall === 'sendto' || event.syscall === 'sendmsg') {
        const size = event.returnCode > 0 ? event.returnCode : 0;
        if (size > 1048576) {
          largeWriteDetected = true;

          for (let j = i + 1; j < Math.min(i + 10, events.length); j++) {
            const nextEvent = events[j]!;
            if (['sendto', 'sendmsg', 'sendmmsg', 'connect', 'socket'].includes(nextEvent.syscall)) {
              networkActivityDetected = true;
              break;
            }
          }
          
          if (networkActivityDetected) break;
        }
      }
    }
    
    return largeWriteDetected && networkActivityDetected;
  }

  detectPrivilegeEscalation(events: SyscallEvent[]): boolean {
    const privSyscalls = ['setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid', 'capset'];
    return events.some(event => privSyscalls.includes(event.syscall));
  }
}
