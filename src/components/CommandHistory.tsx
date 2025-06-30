
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { History, Copy, Terminal } from 'lucide-react';

interface GeneratedCommand {
  id: string;
  prompt: string;
  command: string;
  explanation: string;
  category: string;
  timestamp: Date;
}

interface CommandHistoryProps {
  commands: GeneratedCommand[];
  onCopy: (text: string) => void;
}

const CommandHistory: React.FC<CommandHistoryProps> = ({ commands, onCopy }) => {
  if (commands.length === 0) {
    return null;
  }

  const recentCommands = commands.slice(0, 5);

  return (
    <Card className="terminal-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <History className="h-5 w-5 text-primary" />
          <span>Recent Commands</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {recentCommands.map((cmd) => (
            <div
              key={cmd.id}
              className="flex items-center space-x-3 p-3 rounded-md bg-muted/50 terminal-border hover:bg-muted/70 transition-colors"
            >
              <Terminal className="h-4 w-4 text-primary flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2 mb-1">
                  <Badge variant="outline" className="text-xs">
                    {cmd.category}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {cmd.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <code className="text-sm font-mono text-primary truncate block">
                  {cmd.command}
                </code>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onCopy(cmd.command)}
                className="flex-shrink-0 text-muted-foreground hover:text-primary"
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default CommandHistory;
