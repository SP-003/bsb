
import React, { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Key, ExternalLink } from 'lucide-react';
import { aiService } from '../services/aiService';

interface ApiKeyInputProps {
  onKeySet: () => void;
}

export const ApiKeyInput: React.FC<ApiKeyInputProps> = ({ onKeySet }) => {
  const [apiKey, setApiKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) return;

    setIsLoading(true);
    try {
      aiService.setApiKey(apiKey.trim());
      onKeySet();
    } catch (error) {
      console.error('Error setting API key:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center">
        <CardTitle className="flex items-center justify-center gap-2">
          <Key className="h-5 w-5" />
          API Key Required
        </CardTitle>
        <CardDescription>
          Enter your Groq API key to enable AI-powered command generation
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-sm text-muted-foreground space-y-2">
          <p>Get a free API key from Groq:</p>
          <Button
            variant="outline"
            size="sm"
            className="w-full"
            onClick={() => window.open('https://console.groq.com/keys', '_blank')}
          >
            <ExternalLink className="h-4 w-4 mr-2" />
            Get Free Groq API Key
          </Button>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-3">
          <Input
            type="password"
            placeholder="Enter your Groq API key"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="font-mono text-sm"
          />
          <Button 
            type="submit" 
            className="w-full" 
            disabled={!apiKey.trim() || isLoading}
          >
            {isLoading ? 'Setting up...' : 'Save API Key'}
          </Button>
        </form>
        
        <p className="text-xs text-muted-foreground text-center">
          Your API key is stored locally in your browser
        </p>
      </CardContent>
    </Card>
  );
};
