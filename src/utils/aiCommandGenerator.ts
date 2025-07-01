
interface CommandResult {
  command: string;
  explanation: string;
  category: string;
}

const commandDatabase = {
  // File Operations
  'file_operations': {
    patterns: ['file', 'copy', 'move', 'delete', 'remove', 'create', 'touch', 'mkdir', 'rmdir', 'chmod', 'chown', 'ls', 'find', 'locate', 'cp', 'mv', 'rm'],
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
        command: 'chown user:group filename',
        explanation: 'Changes the ownership of a file to the specified user and group.',
        category: 'File Operations'
      }
    ]
  },

  // Network Operations
  'network_operations': {
    patterns: ['network', 'ping', 'wget', 'curl', 'ssh', 'scp', 'rsync', 'netstat', 'ss', 'iptables', 'firewall', 'port', 'connection'],
    commands: [
      {
        command: 'ping -c 4 google.com',
        explanation: 'Sends 4 ICMP echo requests to google.com to test network connectivity.',
        category: 'Network Operations'
      },
      {
        command: 'curl -I https://example.com',
        explanation: 'Retrieves HTTP headers from the specified URL without downloading the content.',
        category: 'Network Operations'
      },
      {
        command: 'wget -r -np -k https://example.com',
        explanation: 'Recursively downloads a website for offline viewing, converting links for local use.',
        category: 'Network Operations'
      },
      {
        command: 'ssh user@hostname',
        explanation: 'Establishes a secure shell connection to a remote server.',
        category: 'Network Operations'
      },
      {
        command: 'netstat -tulpn',
        explanation: 'Shows all listening ports and their associated processes.',
        category: 'Network Operations'
      }
    ]
  },

  // System Monitoring
  'system_monitoring': {
    patterns: ['system', 'process', 'memory', 'cpu', 'disk', 'monitor', 'top', 'htop', 'ps', 'kill', 'df', 'du', 'free', 'uptime', 'load'],
    commands: [
      {
        command: 'top',
        explanation: 'Displays real-time information about running processes, CPU usage, and memory consumption.',
        category: 'System Monitoring'
      },
      {
        command: 'ps aux | grep process_name',
        explanation: 'Shows all running processes and filters for a specific process name.',
        category: 'System Monitoring'
      },
      {
        command: 'df -h',
        explanation: 'Displays disk space usage for all mounted filesystems in human-readable format.',
        category: 'System Monitoring'
      },
      {
        command: 'free -h',
        explanation: 'Shows memory usage including RAM and swap in human-readable format.',
        category: 'System Monitoring'
      },
      {
        command: 'du -sh /path/*',
        explanation: 'Shows disk usage of all items in the specified directory in human-readable format.',
        category: 'System Monitoring'
      }
    ]
  },

  // Text Processing
  'text_processing': {
    patterns: ['text', 'grep', 'sed', 'awk', 'cat', 'head', 'tail', 'sort', 'uniq', 'wc', 'cut', 'tr', 'search', 'replace', 'filter'],
    commands: [
      {
        command: 'grep -r "search_term" /path',
        explanation: 'Recursively searches for a specific term in all files within the specified directory.',
        category: 'Text Processing'
      },
      {
        command: 'sed -i "s/old_text/new_text/g" filename',
        explanation: 'Replaces all occurrences of old_text with new_text in the specified file.',
        category: 'Text Processing'
      },
      {
        command: 'awk "{print $1}" filename',
        explanation: 'Prints the first column of each line from the specified file.',
        category: 'Text Processing'
      },
      {
        command: 'tail -f /var/log/syslog',
        explanation: 'Continuously displays the last lines of the system log as new entries are added.',
        category: 'Text Processing'
      },
      {
        command: 'sort filename | uniq -c',
        explanation: 'Sorts the file contents and counts duplicate lines.',
        category: 'Text Processing'
      }
    ]
  },

  // Archive Operations
  'archive_operations': {
    patterns: ['archive', 'compress', 'extract', 'zip', 'unzip', 'tar', 'gzip', 'gunzip', 'backup'],
    commands: [
      {
        command: 'tar -czf archive.tar.gz /path/to/directory',
        explanation: 'Creates a compressed tar archive of the specified directory.',
        category: 'Archive Operations'
      },
      {
        command: 'tar -xzf archive.tar.gz',
        explanation: 'Extracts a compressed tar archive to the current directory.',
        category: 'Archive Operations'
      },
      {
        command: 'zip -r archive.zip /path/to/directory',
        explanation: 'Creates a ZIP archive of the specified directory and its contents.',
        category: 'Archive Operations'
      },
      {
        command: 'unzip archive.zip -d /destination/path',
        explanation: 'Extracts a ZIP archive to the specified destination directory.',
        category: 'Archive Operations'
      }
    ]
  },

  // Security & Permissions
  'security_operations': {
    patterns: ['security', 'permission', 'user', 'group', 'sudo', 'su', 'passwd', 'useradd', 'usermod', 'userdel', 'groups', 'id', 'whoami'],
    commands: [
      {
        command: 'sudo useradd -m -s /bin/bash username',
        explanation: 'Creates a new user with a home directory and bash shell.',
        category: 'Security Operations'
      },
      {
        command: 'sudo passwd username',
        explanation: 'Changes the password for the specified user.',
        category: 'Security Operations'
      },
      {
        command: 'groups username',
        explanation: 'Shows all groups that the specified user belongs to.',
        category: 'Security Operations'
      },
      {
        command: 'find / -perm -4000 2>/dev/null',
        explanation: 'Finds all files with SUID bit set, which could be potential security risks.',
        category: 'Security Operations'
      }
    ]
  },

  // Service Management
  'service_management': {
    patterns: ['service', 'systemd', 'systemctl', 'daemon', 'start', 'stop', 'restart', 'enable', 'disable', 'status'],
    commands: [
      {
        command: 'systemctl status service_name',
        explanation: 'Shows the current status of a systemd service.',
        category: 'Service Management'
      },
      {
        command: 'sudo systemctl restart service_name',
        explanation: 'Restarts the specified systemd service.',
        category: 'Service Management'
      },
      {
        command: 'sudo systemctl enable service_name',
        explanation: 'Enables a service to start automatically at boot.',
        category: 'Service Management'
      },
      {
        command: 'journalctl -u service_name -f',
        explanation: 'Shows real-time logs for the specified systemd service.',
        category: 'Service Management'
      }
    ]
  },

  // Package Management
  'package_management': {
    patterns: ['package', 'install', 'update', 'upgrade', 'remove', 'apt', 'yum', 'dnf', 'pacman', 'zypper', 'snap'],
    commands: [
      {
        command: 'sudo apt update && sudo apt upgrade',
        explanation: 'Updates the package list and upgrades all installed packages on Debian/Ubuntu systems.',
        category: 'Package Management'
      },
      {
        command: 'sudo apt install package_name',
        explanation: 'Installs a package using the APT package manager.',
        category: 'Package Management'
      },
      {
        command: 'sudo apt remove package_name',
        explanation: 'Removes an installed package using APT.',
        category: 'Package Management'
      },
      {
        command: 'apt search keyword',
        explanation: 'Searches for packages containing the specified keyword.',
        category: 'Package Management'
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
    command: 'echo "Command not found. Please try a more specific prompt."',
    explanation: `No matching command found for "${prompt}". Try using keywords like: file operations (ls, cp, mv), network (ping, curl, ssh), system monitoring (top, ps, df), text processing (grep, sed, awk), or package management (apt, yum). Be more specific about what you want to accomplish.`,
    category: 'Help'
  };
}
