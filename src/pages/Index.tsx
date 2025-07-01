
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Terminal, Shield, Copy, Zap, AlertTriangle, Info } from 'lucide-react';
import { toast } from 'sonner';
import CommandHistory from '@/components/CommandHistory';
import EthicalDisclaimer from '@/components/EthicalDisclaimer';
import AboutSection from '@/components/AboutSection';
import { generateBashCommand } from '@/utils/aiCommandGenerator';

interface GeneratedCommand {
  id: string;
  prompt: string;
  command: string;
  explanation: string;
  category: string;
  timestamp: Date;
}

const Index = () => {
  const [prompt, setPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedCommands, setGeneratedCommands] = useState<GeneratedCommand[]>([]);
  const [showDisclaimer, setShowDisclaimer] = useState(true);
  const [showAbout, setShowAbout] = useState(false);

  const handleGenerate = async () => {
    if (!prompt.trim()) {
      toast.error('Please enter a prompt');
      return;
    }

    setIsGenerating(true);
    try {
      const result = await generateBashCommand(prompt);
      const newCommand: GeneratedCommand = {
        id: Date.now().toString(),
        prompt,
        command: result.command,
        explanation: result.explanation,
        category: result.category,
        timestamp: new Date(),
      };

      setGeneratedCommands(prev => [newCommand, ...prev]);
      setPrompt('');
      toast.success('Command generated successfully!');
    } catch (error) {
      toast.error('Failed to generate command. Please try again.');
      console.error('Generation error:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success('Copied to clipboard!');
    } catch (error) {
      toast.error('Failed to copy to clipboard');
    }
  };

  const clearHistory = () => {
    setGeneratedCommands([]);
    toast.success('Command history cleared!');
  };

  if (showDisclaimer) {
    return <EthicalDisclaimer onAccept={() => setShowDisclaimer(false)} />;
  }

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <Terminal className="h-12 w-12 text-primary glow-text" />
            <h1 className="text-5xl font-bold glow-text">
              Bash Wizard
            </h1>
          </div>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Generate Linux terminal commands for ethical hacking and security research.
            Powered by AI, guided by ethics.
          </p>
          <div className="flex items-center justify-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-primary" />
              <Badge variant="outline" className="terminal-border text-primary">
                Ethical Use Only
              </Badge>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowAbout(!showAbout)}
              className="terminal-border"
            >
              <Info className="h-4 w-4 mr-2" />
              {showAbout ? 'Hide' : 'Show'} About
            </Button>
          </div>
        </div>

        {/* About Section */}
        {showAbout && <AboutSection />}

        {/* Main Input Section */}
        <Card className="terminal-border pulse-glow bg-card">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Zap className="h-5 w-5 text-primary" />
              <span>Generate Command</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Describe what you want to accomplish:
              </label>
              <Textarea
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="e.g., Scan for open ports on a network range, Check SSL certificate expiration, Monitor system logs for suspicious activity..."
                className="min-h-[100px] terminal-border bg-input text-foreground resize-none"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && e.ctrlKey) {
                    handleGenerate();
                  }
                }}
              />
              <p className="text-xs text-muted-foreground">
                Press Ctrl+Enter to generate • Be specific about your security testing needs
              </p>
            </div>
            <Button
              onClick={handleGenerate}
              disabled={isGenerating || !prompt.trim()}
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold"
            >
              {isGenerating ? (
                <>
                  <div className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                  Generating Command...
                </>
              ) : (
                <>
                  <Terminal className="h-4 w-4 mr-2" />
                  Generate Bash Command
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Generated Commands */}
        {generatedCommands.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-2xl font-bold text-primary glow-text">Generated Commands</h2>
            {generatedCommands.map((cmd) => (
              <Card key={cmd.id} className="terminal-border bg-card">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <CardTitle className="text-lg">{cmd.prompt}</CardTitle>
                      <div className="flex items-center space-x-2">
                        <Badge variant="secondary" className="terminal-border">
                          {cmd.category}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {cmd.timestamp.toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="font-semibold text-primary">Command:</h4>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(cmd.command)}
                        className="text-muted-foreground hover:text-primary"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="bg-muted p-4 rounded-md terminal-border">
                      <code className="text-primary font-mono text-sm whitespace-pre-wrap">
                        {cmd.command}
                      </code>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h4 className="font-semibold text-primary">Explanation:</h4>
                    <p className="text-muted-foreground text-sm leading-relaxed">
                      {cmd.explanation}
                    </p>
                  </div>
                  <div className="flex items-center space-x-2 text-yellow-500">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="text-xs">
                      Always test in authorized environments only
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Command History Component */}
        <CommandHistory 
          commands={generatedCommands} 
          onCopy={copyToClipboard}
          onClear={clearHistory}
        />

        {/* Footer */}
        <div className="text-center py-8 border-t border-border">
          <p className="text-muted-foreground text-sm">
            Built for ethical security professionals • Use responsibly • Test only on authorized systems
          </p>
        </div>
      </div>
    </div>
  );
};

export default Index;
