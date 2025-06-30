
interface CommandResult {
  command: string;
  explanation: string;
  category: string;
}

const commandTemplates = {
  'network_scanning': {
    patterns: ['scan', 'network', 'port', 'discover', 'hosts', 'nmap', 'ping'],
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
    patterns: ['ssl', 'certificate', 'tls', 'https', 'cert'],
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
    patterns: ['log', 'monitor', 'suspicious', 'activity', 'auth', 'syslog', 'journal'],
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
    patterns: ['vulnerability', 'vuln', 'security', 'exploit', 'nikto', 'burp'],
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
    patterns: ['harden', 'secure', 'permissions', 'firewall', 'ufw', 'iptables'],
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
  },
  'file_analysis': {
    patterns: ['file', 'search', 'find', 'locate', 'grep', 'analysis'],
    commands: [
      {
        command: 'find /home -name "*.sh" -type f -executable',
        explanation: 'Searches for executable shell scripts in the /home directory, useful for finding potential backdoors or suspicious scripts.',
        category: 'File Analysis'
      },
      {
        command: 'grep -r "password\\|secret\\|key" /var/log/ 2>/dev/null',
        explanation: 'Searches for sensitive information like passwords, secrets, or keys in log files.',
        category: 'File Analysis'
      }
    ]
  }
};

export async function generateBashCommand(prompt: string): Promise<CommandResult> {
  // Ensure prompt is a string and handle edge cases
  const cleanPrompt = String(prompt || '').trim().toLowerCase();
  
  if (!cleanPrompt) {
    throw new Error('Please provide a valid prompt');
  }

  // Enhanced pattern matching with better scoring
  let bestMatch = null;
  let bestScore = 0;

  for (const [category, data] of Object.entries(commandTemplates)) {
    let score = 0;
    for (const pattern of data.patterns) {
      if (cleanPrompt.includes(pattern)) {
        score += pattern.length; // Longer matches get higher scores
      }
    }
    
    if (score > bestScore) {
      bestScore = score;
      bestMatch = { category, data };
    }
  }

  // If we found a good match, use it
  if (bestMatch && bestScore > 0) {
    const randomCommand = bestMatch.data.commands[Math.floor(Math.random() * bestMatch.data.commands.length)];
    
    // Enhanced placeholder replacement
    let command = randomCommand.command;
    command = command.replace(/\{\{target\}\}/g, 'TARGET_IP_OR_DOMAIN');
    command = command.replace(/\{\{domain\}\}/g, 'example.com');
    command = command.replace(/\{\{network_range\}\}/g, '192.168.1.0/24');
    command = command.replace(/\{\{target_url\}\}/g, 'https://example.com');
    
    return {
      command,
      explanation: randomCommand.explanation,
      category: randomCommand.category
    };
  }
  
  // Enhanced default fallback commands with better variety
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
    },
    {
      command: 'ss -tuln | grep -E ":22|:80|:443"',
      explanation: 'Shows listening sockets for common services (SSH, HTTP, HTTPS) using the modern ss command.',
      category: 'Network Analysis'
    },
    {
      command: 'last -n 20',
      explanation: 'Shows the last 20 login sessions, useful for detecting unauthorized access attempts.',
      category: 'Access Monitoring'
    }
  ];
  
  const randomDefault = defaultCommands[Math.floor(Math.random() * defaultCommands.length)];
  return randomDefault;
}
