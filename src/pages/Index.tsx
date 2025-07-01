
import { useState, useEffect } from 'react';
import { CommandInput } from '../components/CommandInput';
import { CommandOutput } from '../components/CommandOutput';
import { CommandHistory } from '../components/CommandHistory';
import { AboutSection } from '../components/AboutSection';
import { EthicalDisclaimer } from '../components/EthicalDisclaimer';
import { ApiKeyInput } from '../components/ApiKeyInput';
import { generateBashCommand } from '../utils/aiCommandGenerator';
import { aiService } from '../services/aiService';
import { toast } from 'sonner';

interface CommandResult {
  command: string;
  explanation: string;
  category: string;
}

const Index = () => {
  const [currentCommand, setCurrentCommand] = useState<CommandResult | null>(null);
  const [commandHistory, setCommandHistory] = useState<CommandResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [hasApiKey, setHasApiKey] = useState(false);

  useEffect(() => {
    setHasApiKey(aiService.hasApiKey());
  }, []);

  const handleCommandSubmit = async (prompt: string) => {
    setIsLoading(true);
    try {
      const result = await generateBashCommand(prompt);
      setCurrentCommand(result);
      setCommandHistory(prev => [result, ...prev.slice(0, 9)]);
    } catch (error) {
      console.error('Error generating command:', error);
      toast.error('Failed to generate command. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleApiKeySet = () => {
    setHasApiKey(true);
    toast.success('API key saved! You can now use AI-powered command generation.');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl md:text-6xl font-bold text-white mb-4">
            <span className="bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">
              Bash Wizard
            </span>
          </h1>
          <p className="text-xl text-gray-300 mb-6">
            AI-Powered Linux Commands for Ethical Hacking and Security Research
          </p>
        </div>

        <EthicalDisclaimer />

        {!hasApiKey && (
          <div className="mb-8">
            <ApiKeyInput onKeySet={handleApiKeySet} />
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-6">
            <CommandInput onSubmit={handleCommandSubmit} isLoading={isLoading} />
            {currentCommand && <CommandOutput {...currentCommand} />}
          </div>
          
          <div className="space-y-6">
            <CommandHistory commands={commandHistory} />
            <AboutSection />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
