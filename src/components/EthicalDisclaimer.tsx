
import React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, AlertTriangle, CheckCircle, Terminal } from 'lucide-react';

interface EthicalDisclaimerProps {
  onAccept: () => void;
}

const EthicalDisclaimer: React.FC<EthicalDisclaimerProps> = ({ onAccept }) => {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="max-w-2xl w-full terminal-border pulse-glow bg-card">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            <Shield className="h-16 w-16 text-primary glow-text" />
          </div>
          <CardTitle className="text-3xl font-bold glow-text">
            Ethical AI Bash Wizard
          </CardTitle>
          <p className="text-muted-foreground">
            AI-Powered Linux Commands for Security Professionals
          </p>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-start space-x-3 p-4 bg-muted/50 rounded-md terminal-border">
              <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="font-semibold text-primary mb-2">Important Disclaimer</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  This tool generates Linux bash commands for ethical hacking and security research purposes only. 
                  You must only use these commands on systems you own or have explicit written permission to test.
                </p>
              </div>
            </div>

            <div className="grid gap-4">
              <h3 className="font-semibold text-primary">Ethical Use Guidelines:</h3>
              
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-muted-foreground">
                    Only test on systems you own or have written authorization to test
                  </p>
                </div>
                
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-muted-foreground">
                    Use for legitimate security research and learning purposes
                  </p>
                </div>
                
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-muted-foreground">
                    Follow responsible disclosure practices for any vulnerabilities found
                  </p>
                </div>
                
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-muted-foreground">
                    Respect privacy and confidentiality of data accessed during testing
                  </p>
                </div>
              </div>
            </div>

            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-md">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-semibold text-red-400 mb-1">Legal Warning</h4>
                  <p className="text-sm text-muted-foreground">
                    Unauthorized access to computer systems is illegal and may result in criminal charges. 
                    The creators of this tool are not responsible for any misuse or illegal activities.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-border">
            <Button
              onClick={onAccept}
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold"
            >
              <Terminal className="h-4 w-4 mr-2" />
              I Understand and Agree to Use Ethically
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EthicalDisclaimer;
