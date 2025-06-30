
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Info, Mail, Book, HelpCircle, Shield, Terminal, Zap } from 'lucide-react';

const AboutSection: React.FC = () => {
  const copyEmail = () => {
    navigator.clipboard.writeText('pramaniksuvadip10@gmail.com');
  };

  return (
    <Card className="terminal-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Info className="h-5 w-5 text-primary" />
          <span>About Ethical AI Bash Wizard</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* App Description */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-primary flex items-center space-x-2">
            <Terminal className="h-5 w-5" />
            <span>What is this tool?</span>
          </h3>
          <p className="text-muted-foreground leading-relaxed">
            The Ethical AI Bash Wizard is an AI-powered command generator designed specifically for 
            cybersecurity professionals, penetration testers, and security researchers. It generates 
            Linux bash commands for ethical hacking, security testing, and system analysis based on 
            natural language prompts.
          </p>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className="terminal-border">
              <Shield className="h-3 w-3 mr-1" />
              Ethical Use Only
            </Badge>
            <Badge variant="outline" className="terminal-border">
              <Zap className="h-3 w-3 mr-1" />
              AI-Powered
            </Badge>
            <Badge variant="outline" className="terminal-border">
              Security Research
            </Badge>
          </div>
        </div>

        {/* How to Use */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-primary flex items-center space-x-2">
            <HelpCircle className="h-5 w-5" />
            <span>How to Use</span>
          </h3>
          <div className="space-y-2 text-muted-foreground">
            <div className="flex items-start space-x-2">
              <span className="text-primary font-semibold">1.</span>
              <span>Enter a descriptive prompt about what you want to accomplish</span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-primary font-semibold">2.</span>
              <span>Click "Generate Bash Command" or press Ctrl+Enter</span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-primary font-semibold">3.</span>
              <span>Review the generated command and explanation</span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-primary font-semibold">4.</span>
              <span>Copy the command and test it in authorized environments only</span>
            </div>
          </div>
        </div>

        {/* Example Prompts */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-primary flex items-center space-x-2">
            <Book className="h-5 w-5" />
            <span>Example Prompts</span>
          </h3>
          <div className="space-y-2">
            <div className="bg-muted p-3 rounded-md terminal-border">
              <code className="text-sm text-primary">"Scan for open ports on a network range"</code>
            </div>
            <div className="bg-muted p-3 rounded-md terminal-border">
              <code className="text-sm text-primary">"Check SSL certificate expiration for a domain"</code>
            </div>
            <div className="bg-muted p-3 rounded-md terminal-border">
              <code className="text-sm text-primary">"Monitor system logs for suspicious login attempts"</code>
            </div>
            <div className="bg-muted p-3 rounded-md terminal-border">
              <code className="text-sm text-primary">"Find files with SUID permissions"</code>
            </div>
          </div>
        </div>

        {/* Supported Categories */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-primary">Supported Categories</h3>
          <div className="grid grid-cols-2 gap-2">
            <Badge variant="secondary" className="justify-center">Network Scanning</Badge>
            <Badge variant="secondary" className="justify-center">SSL/TLS Analysis</Badge>
            <Badge variant="secondary" className="justify-center">Log Monitoring</Badge>
            <Badge variant="secondary" className="justify-center">Vulnerability Scanning</Badge>
            <Badge variant="secondary" className="justify-center">System Hardening</Badge>
            <Badge variant="secondary" className="justify-center">File Analysis</Badge>
          </div>
        </div>

        {/* Contact Information */}
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-primary flex items-center space-x-2">
            <Mail className="h-5 w-5" />
            <span>Contact</span>
          </h3>
          <div className="flex items-center space-x-3">
            <span className="text-muted-foreground">Developer:</span>
            <Button
              variant="outline"
              size="sm"
              onClick={copyEmail}
              className="terminal-border hover:bg-primary/10"
            >
              <Mail className="h-4 w-4 mr-2" />
              pramaniksuvadip10@gmail.com
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Click to copy email address
          </p>
        </div>

        {/* Disclaimer */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 p-4 rounded-md">
          <p className="text-yellow-600 text-sm font-medium">
            ⚠️ Important: This tool is designed for ethical hacking and authorized security testing only. 
            Always ensure you have proper authorization before running any security commands on systems 
            you do not own.
          </p>
        </div>
      </CardContent>
    </Card>
  );
};

export default AboutSection;
