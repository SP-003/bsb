
interface CommandResult {
  command: string;
  explanation: string;
  category: string;
}

const commandTemplates = {
  'network_scanning': {
    patterns: ['scan', 'network', 'port', 'discover', 'hosts'],
    commands: [
      {
        command: 'nmap -sS -sV -O {{target}}',
        explanation: 'Performs a TCP SYN scan to detect open ports, service versions, and operating system on the target. The -sS flag uses stealth scanning, -sV detects service versions, and -O attempts OS detection.',
        category: 'Network Scanning'
      },
      {
        command: 'nmap -sn {{network_range}}',
        explanation: 'Performs a ping scan to discover live hosts in the network range without port scanning. Useful for initial network reconnaissance.',
        category: 'Network Discovery'
      }
    ]
  },
  'ssl_analysis': {
    patterns: ['ssl', 'certificate', 'tls', 'https'],
    commands: [
      {
        command: 'openssl s_client -connect {{domain}}:443 -servername {{domain}} | openssl x509 -noout -dates',
        explanation: 'Connects to the SSL/TLS service and extracts certificate validity dates to check for expiration.',
        category: 'SSL Analysis'
      },
      {
        command: 'sslscan {{domain}}:443',
        explanation: 'Performs comprehensive SSL/TLS configuration analysis including supported ciphers, protocols, and vulnerabilities.',
        category: 'SSL Analysis'
      }
    ]
  },
  'log_monitoring': {
    patterns: ['log', 'monitor', 'suspicious', 'activity', 'auth'],
    commands: [
      {
        command: 'tail -f /var/log/auth.log | grep -i "failed\\|invalid\\|error"',
        explanation: 'Monitors authentication logs in real-time and filters for failed login attempts, invalid users, and errors.',
        category: 'Log Monitoring'
      },
      {
        command: 'journalctl -f -u ssh.service | grep -E "(Failed|Invalid|Connection closed)"',
        explanation: 'Monitors SSH service logs in real-time using systemd journal, filtering for connection failures and invalid attempts.',
        category: 'Log Monitoring'
      }
    ]
  },
  'vulnerability_scanning': {
    patterns: ['vulnerability', 'vuln', 'security', 'exploit'],
    commands: [
      {
        command: 'nikto -h {{target_url}}',
        explanation: 'Performs web vulnerability scanning against the target URL, checking for common web server vulnerabilities and misconfigurations.',
        category: 'Vulnerability Scanning'
      },
      {
        command: 'nmap --script vuln {{target}}',
        explanation: 'Uses Nmap\'s vulnerability detection scripts to identify known vulnerabilities on the target system.',
        category: 'Vulnerability Scanning'
      }
    ]
  },
  'system_hardening': {
    patterns: ['harden', 'secure', 'permissions', 'firewall'],
    commands: [
      {
        command: 'find / -type f -perm -4000 2>/dev/null',
        explanation: 'Finds all files with SUID bit set, which could potentially be exploited for privilege escalation.',
        category: 'System Hardening'
      },
      {
        command: 'ufw status verbose && ufw --dry-run enable',
        explanation: 'Shows current firewall status and simulates enabling UFW without actually applying changes.',
        category: 'System Hardening'
      }
    ]
  }
};

export async function generateBashCommand(prompt: string): Promise<CommandResult> {
  const lowerPrompt = prompt.toLowerCase();
  
  // Simple pattern matching to determine category
  for (const [category, data] of Object.entries(commandTemplates)) {
    if (data.patterns.some(pattern => lowerPrompt.includes(pattern))) {
      const randomCommand = data.commands[Math.floor(Math.random() * data.commands.length)];
      
      // Simple placeholder replacement
      let command = randomCommand.command;
      if (command.includes('{{target}}')) {
        command = command.replace(/\{\{target\}\}/g, 'TARGET_IP_OR_DOMAIN');
      }
      if (command.includes('{{domain}}')) {
        command = command.replace(/\{\{domain\}\}/g, 'example.com');
      }
      if (command.includes('{{network_range}}')) {
        command = command.replace(/\{\{network_range\}\}/g, '192.168.1.0/24');
      }
      if (command.includes('{{target_url}}')) {
        command = command.replace(/\{\{target_url\}\}/g, 'https://example.com');
      }
      
      return {
        command,
        explanation: randomCommand.explanation,
        category: randomCommand.category
      };
    }
  }
  
  // Default fallback for general security commands
  const defaultCommands = [
    {
      command: 'ps aux | grep -v grep | grep -E "(suspicious_process_name)"',
      explanation: 'Searches for specific processes that might indicate malicious activity. Replace "suspicious_process_name" with actual process names you want to monitor.',
      category: 'Process Monitoring'
    },
    {
      command: 'netstat -tulpn | grep LISTEN',
      explanation: 'Shows all listening ports and associated processes, useful for identifying unexpected network services.',
      category: 'Network Analysis'
    },
    {
      command: 'ls -la /tmp && find /tmp -type f -executable',
      explanation: 'Lists contents of /tmp directory and finds executable files, which could indicate malicious activity.',
      category: 'File Analysis'
    }
  ];
  
  const randomDefault = defaultCommands[Math.floor(Math.random() * defaultCommands.length)];
  return randomDefault;
}
