
interface CommandResult {
  command: string;
  explanation: string;
  category: string;
}

const commandDatabase = {
  // File Operations
  'file_operations': {
    patterns: ['file', 'copy', 'move', 'delete', 'remove', 'create', 'touch', 'mkdir', 'rmdir', 'chmod', 'chown', 'ls', 'find', 'locate', 'cp', 'mv', 'rm', 'ln', 'stat', 'tree', 'file', 'which', 'whereis'],
    commands: [
      {
        command: 'ls -la',
        explanation: 'Lists all files and directories in long format, including hidden files, with detailed permissions and ownership information.',
        category: 'File Operations'
      },
      {
        command: 'find /path -name "*.txt" -type f',
        explanation: 'Searches for all .txt files in the specified path and subdirectories.',
        category: 'File Operations'
      },
      {
        command: 'cp -r source_directory destination_directory',
        explanation: 'Recursively copies a directory and all its contents to a new location.',
        category: 'File Operations'
      },
      {
        command: 'chmod 755 filename',
        explanation: 'Changes file permissions to read, write, execute for owner and read, execute for group and others.',
        category: 'File Operations'
      },
      {
        command: 'tree -L 2',
        explanation: 'Displays directory structure in tree format, limiting depth to 2 levels.',
        category: 'File Operations'
      },
      {
        command: 'stat filename',
        explanation: 'Displays detailed information about a file including size, permissions, timestamps, and inode.',
        category: 'File Operations'
      },
      {
        command: 'ln -s /path/to/original /path/to/link',
        explanation: 'Creates a symbolic link from the original file to the specified location.',
        category: 'File Operations'
      }
    ]
  },

  // Network Operations
  'network_operations': {
    patterns: ['network', 'ping', 'wget', 'curl', 'ssh', 'scp', 'rsync', 'netstat', 'ss', 'iptables', 'firewall', 'port', 'connection', 'nmap', 'dig', 'nslookup', 'telnet', 'ftp', 'sftp', 'nc', 'netcat', 'traceroute', 'mtr', 'whois', 'tcpdump', 'wireshark'],
    commands: [
      {
        command: 'nmap -sn 192.168.1.0/24',
        explanation: 'Performs a ping scan to discover live hosts in the specified network range.',
        category: 'Network Operations'
      },
      {
        command: 'nmap -sS -sV -O target_ip',
        explanation: 'Performs TCP SYN scan with version detection and OS fingerprinting on target.',
        category: 'Network Operations'
      },
      {
        command: 'dig google.com',
        explanation: 'Performs DNS lookup for google.com showing detailed DNS record information.',
        category: 'Network Operations'
      },
      {
        command: 'netstat -tulpn',
        explanation: 'Shows all listening ports and their associated processes.',
        category: 'Network Operations'
      },
      {
        command: 'ss -tuln',
        explanation: 'Modern replacement for netstat, shows socket statistics for TCP and UDP.',
        category: 'Network Operations'
      },
      {
        command: 'tcpdump -i eth0 -w capture.pcap',
        explanation: 'Captures network packets on eth0 interface and saves to file for analysis.',
        category: 'Network Operations'
      },
      {
        command: 'nc -l -p 4444',
        explanation: 'Creates a netcat listener on port 4444 for reverse shell or file transfer.',
        category: 'Network Operations'
      },
      {
        command: 'traceroute google.com',
        explanation: 'Traces the network path to google.com showing all intermediate hops.',
        category: 'Network Operations'
      }
    ]
  },

  // System Monitoring
  'system_monitoring': {
    patterns: ['system', 'process', 'memory', 'cpu', 'disk', 'monitor', 'top', 'htop', 'ps', 'kill', 'df', 'du', 'free', 'uptime', 'load', 'iostat', 'vmstat', 'sar', 'lsof', 'who', 'w', 'last', 'history'],
    commands: [
      {
        command: 'htop',
        explanation: 'Interactive process viewer with color-coded display of CPU, memory usage and system load.',
        category: 'System Monitoring'
      },
      {
        command: 'ps aux --sort=-%cpu | head -10',
        explanation: 'Shows top 10 processes consuming the most CPU resources.',
        category: 'System Monitoring'
      },
      {
        command: 'lsof -i :80',
        explanation: 'Lists all processes using port 80, useful for identifying web server processes.',
        category: 'System Monitoring'
      },
      {
        command: 'iostat -x 1',
        explanation: 'Displays extended I/O statistics for all devices, updating every second.',
        category: 'System Monitoring'
      },
      {
        command: 'vmstat 1 5',
        explanation: 'Shows virtual memory statistics for 5 iterations with 1 second intervals.',
        category: 'System Monitoring'
      },
      {
        command: 'sar -u 1 10',
        explanation: 'Displays CPU utilization statistics every second for 10 iterations.',
        category: 'System Monitoring'
      },
      {
        command: 'who -a',
        explanation: 'Shows all currently logged in users with detailed login information.',
        category: 'System Monitoring'
      }
    ]
  },

  // Text Processing
  'text_processing': {
    patterns: ['text', 'grep', 'sed', 'awk', 'cat', 'head', 'tail', 'sort', 'uniq', 'wc', 'cut', 'tr', 'search', 'replace', 'filter', 'less', 'more', 'vim', 'nano', 'emacs'],
    commands: [
      {
        command: 'grep -r "ERROR" /var/log/',
        explanation: 'Recursively searches for "ERROR" in all log files under /var/log directory.',
        category: 'Text Processing'
      },
      {
        command: 'sed -i "s/old_text/new_text/g" filename',
        explanation: 'Replaces all occurrences of old_text with new_text in the specified file.',
        category: 'Text Processing'
      },
      {
        command: 'awk "{print $1, $3}" /etc/passwd',
        explanation: 'Prints the first and third columns from /etc/passwd file (username and UID).',
        category: 'Text Processing'
      },
      {
        command: 'tail -f /var/log/syslog',
        explanation: 'Continuously displays the last lines of the system log as new entries are added.',
        category: 'Text Processing'
      },
      {
        command: 'sort filename | uniq -c | sort -nr',
        explanation: 'Sorts file, counts duplicate lines, then sorts by frequency in descending order.',
        category: 'Text Processing'
      },
      {
        command: 'cut -d: -f1 /etc/passwd',
        explanation: 'Extracts usernames from /etc/passwd by cutting the first field using colon delimiter.',
        category: 'Text Processing'
      }
    ]
  },

  // Archive Operations
  'archive_operations': {
    patterns: ['archive', 'compress', 'extract', 'zip', 'unzip', 'tar', 'gzip', 'gunzip', 'backup', '7z', 'rar', 'bzip2'],
    commands: [
      {
        command: 'tar -czf backup.tar.gz /home/user/',
        explanation: 'Creates a compressed tar archive of the user home directory.',
        category: 'Archive Operations'
      },
      {
        command: 'tar -xzf archive.tar.gz -C /destination/',
        explanation: 'Extracts a compressed tar archive to the specified destination directory.',
        category: 'Archive Operations'
      },
      {
        command: 'zip -r archive.zip /path/to/directory',
        explanation: 'Creates a ZIP archive of the specified directory and its contents.',
        category: 'Archive Operations'
      },
      {
        command: '7z a -t7z archive.7z /path/to/directory/',
        explanation: 'Creates a 7z archive with maximum compression of the specified directory.',
        category: 'Archive Operations'
      }
    ]
  },

  // Security & Permissions
  'security_operations': {
    patterns: ['security', 'permission', 'user', 'group', 'sudo', 'su', 'passwd', 'useradd', 'usermod', 'userdel', 'groups', 'id', 'whoami', 'chroot', 'umask', 'acl', 'selinux', 'apparmor'],
    commands: [
      {
        command: 'find / -perm -4000 2>/dev/null',
        explanation: 'Finds all files with SUID bit set, which could be potential security risks.',
        category: 'Security Operations'
      },
      {
        command: 'sudo useradd -m -s /bin/bash -G sudo username',
        explanation: 'Creates a new user with home directory, bash shell, and sudo privileges.',
        category: 'Security Operations'
      },
      {
        command: 'getfacl filename',
        explanation: 'Displays Access Control List (ACL) permissions for the specified file.',
        category: 'Security Operations'
      },
      {
        command: 'chattr +i filename',
        explanation: 'Makes a file immutable, preventing it from being modified or deleted.',
        category: 'Security Operations'
      },
      {
        command: 'last -n 10',
        explanation: 'Shows the last 10 login sessions, useful for security auditing.',
        category: 'Security Operations'
      }
    ]
  },

  // Service Management
  'service_management': {
    patterns: ['service', 'systemd', 'systemctl', 'daemon', 'start', 'stop', 'restart', 'enable', 'disable', 'status', 'journalctl', 'cron', 'crontab', 'at', 'batch'],
    commands: [
      {
        command: 'systemctl --failed',
        explanation: 'Lists all failed systemd services that need attention.',
        category: 'Service Management'
      },
      {
        command: 'journalctl -u apache2 --since "1 hour ago"',
        explanation: 'Shows logs for apache2 service from the last hour.',
        category: 'Service Management'
      },
      {
        command: 'crontab -l',
        explanation: 'Lists all scheduled cron jobs for the current user.',
        category: 'Service Management'
      },
      {
        command: 'systemctl list-units --type=service --state=running',
        explanation: 'Lists all currently running systemd services.',
        category: 'Service Management'
      }
    ]
  },

  // Package Management
  'package_management': {
    patterns: ['package', 'install', 'update', 'upgrade', 'remove', 'apt', 'yum', 'dnf', 'pacman', 'zypper', 'snap', 'flatpak', 'pip', 'npm', 'gem'],
    commands: [
      {
        command: 'apt list --upgradable',
        explanation: 'Shows all packages that have available updates on Debian/Ubuntu systems.',
        category: 'Package Management'
      },
      {
        command: 'dnf search keyword',
        explanation: 'Searches for packages containing the keyword in Fedora/RHEL systems.',
        category: 'Package Management'
      },
      {
        command: 'snap list',
        explanation: 'Lists all installed snap packages with their versions.',
        category: 'Package Management'
      },
      {
        command: 'pip list --outdated',
        explanation: 'Shows all outdated Python packages installed via pip.',
        category: 'Package Management'
      }
    ]
  },

  // Database Operations
  'database_operations': {
    patterns: ['database', 'mysql', 'postgresql', 'sqlite', 'mongo', 'redis', 'sql', 'backup', 'dump', 'restore'],
    commands: [
      {
        command: 'mysqldump -u root -p database_name > backup.sql',
        explanation: 'Creates a backup of MySQL database to a SQL file.',
        category: 'Database Operations'
      },
      {
        command: 'pg_dump -U username database_name > backup.sql',
        explanation: 'Creates a backup of PostgreSQL database to a SQL file.',
        category: 'Database Operations'
      },
      {
        command: 'sqlite3 database.db ".dump" > backup.sql',
        explanation: 'Creates a backup of SQLite database to a SQL file.',
        category: 'Database Operations'
      },
      {
        command: 'redis-cli --rdb backup.rdb',
        explanation: 'Creates a backup of Redis database in RDB format.',
        category: 'Database Operations'
      }
    ]
  },

  // Web Server Operations
  'web_server_operations': {
    patterns: ['apache', 'nginx', 'web', 'server', 'http', 'https', 'ssl', 'certificate', 'vhost', 'site'],
    commands: [
      {
        command: 'apache2ctl configtest',
        explanation: 'Tests Apache configuration files for syntax errors.',
        category: 'Web Server Operations'
      },
      {
        command: 'nginx -t',
        explanation: 'Tests Nginx configuration files for syntax errors.',
        category: 'Web Server Operations'
      },
      {
        command: 'openssl x509 -in certificate.crt -text -noout',
        explanation: 'Displays detailed information about an SSL certificate.',
        category: 'Web Server Operations'
      },
      {
        command: 'curl -I -k https://example.com',
        explanation: 'Retrieves HTTP headers from HTTPS site, ignoring SSL certificate errors.',
        category: 'Web Server Operations'
      }
    ]
  },

  // System Information
  'system_information': {
    patterns: ['info', 'information', 'version', 'kernel', 'hardware', 'cpu', 'memory', 'disk', 'uname', 'lscpu', 'lsblk', 'lsusb', 'lspci', 'dmidecode'],
    commands: [
      {
        command: 'uname -a',
        explanation: 'Displays complete system information including kernel version and architecture.',
        category: 'System Information'
      },
      {
        command: 'lscpu',
        explanation: 'Displays detailed CPU architecture and feature information.',
        category: 'System Information'
      },
      {
        command: 'lsblk',
        explanation: 'Lists all block devices in tree format showing disk partitioning.',
        category: 'System Information'
      },
      {
        command: 'dmidecode -t memory',
        explanation: 'Shows detailed memory information including type, speed, and slots.',
        category: 'System Information'
      },
      {
        command: 'lshw -short',
        explanation: 'Displays hardware information in short format.',
        category: 'System Information'
      }
    ]
  },

  // Development Tools
  'development_tools': {
    patterns: ['git', 'docker', 'kubernetes', 'k8s', 'make', 'gcc', 'python', 'node', 'java', 'build', 'compile', 'debug'],
    commands: [
      {
        command: 'git log --oneline --graph --all',
        explanation: 'Shows git commit history in a compact graphical format for all branches.',
        category: 'Development Tools'
      },
      {
        command: 'docker ps -a',
        explanation: 'Lists all Docker containers including stopped ones.',
        category: 'Development Tools'
      },
      {
        command: 'kubectl get pods --all-namespaces',
        explanation: 'Lists all Kubernetes pods across all namespaces.',
        category: 'Development Tools'
      },
      {
        command: 'make clean && make',
        explanation: 'Cleans previous build artifacts and compiles the project.',
        category: 'Development Tools'
      },
      {
        command: 'strace -p PID',
        explanation: 'Traces system calls made by a running process for debugging.',
        category: 'Development Tools'
      }
    ]
  }
};

export async function generateBashCommand(prompt: string): Promise<CommandResult> {
  const cleanPrompt = String(prompt || '').trim().toLowerCase();
  
  if (!cleanPrompt) {
    throw new Error('Please provide a valid prompt');
  }

  // Enhanced pattern matching with scoring
  let bestMatch = null;
  let bestScore = 0;
  let matchedKeywords: string[] = [];

  for (const [category, data] of Object.entries(commandDatabase)) {
    let score = 0;
    let currentKeywords: string[] = [];
    
    for (const pattern of data.patterns) {
      if (cleanPrompt.includes(pattern)) {
        score += pattern.length * 2; // Weight longer matches more heavily
        currentKeywords.push(pattern);
      }
    }
    
    if (score > bestScore) {
      bestScore = score;
      bestMatch = { category, data };
      matchedKeywords = currentKeywords;
    }
  }

  // If we found a good match, use it
  if (bestMatch && bestScore > 0) {
    const randomCommand = bestMatch.data.commands[Math.floor(Math.random() * bestMatch.data.commands.length)];
    return {
      command: randomCommand.command,
      explanation: randomCommand.explanation,
      category: randomCommand.category
    };
  }
  
  // Better default response when no match is found
  return {
    command: 'echo "No matching command found. Try being more specific."',
    explanation: `I couldn't find a matching command for "${prompt}". Try using specific keywords like: nmap (network scanning), grep (text search), systemctl (service management), docker (containers), git (version control), find (file search), ps (processes), netstat (network connections), or describe your task more specifically (e.g., "scan network for open ports", "search for text in files", "monitor CPU usage").`,
    category: 'Help'
  };
}
