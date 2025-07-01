
interface AIResponse {
  command: string;
  explanation: string;
  category: string;
}

export class AIService {
  private apiKey: string | null = null;
  private baseUrl = 'https://api.groq.com/openai/v1/chat/completions';

  constructor() {
    this.apiKey = localStorage.getItem('groq_api_key');
  }

  setApiKey(key: string) {
    this.apiKey = key;
    localStorage.setItem('groq_api_key', key);
  }

  hasApiKey(): boolean {
    return !!this.apiKey;
  }

  async generateCommand(prompt: string): Promise<AIResponse> {
    if (!this.apiKey) {
      throw new Error('API key not set');
    }

    const systemPrompt = `You are a Linux command expert specializing in security, penetration testing, and system administration.

Generate a bash command that matches the user's request. Respond with a JSON object containing:
- "command": the exact bash command
- "explanation": clear explanation of what the command does
- "category": category like "Network Operations", "File Operations", "Security Operations", etc.

Focus on popular tools like: nmap, metasploit, meterpreter, docker, grep, find, systemctl, etc.

Examples:
{"command": "nmap -sS target.com", "explanation": "Performs TCP SYN scan on target.com to identify open ports", "category": "Network Operations"}
{"command": "find /var/log -name '*.log' -mtime -1", "explanation": "Finds all log files modified in the last 24 hours", "category": "File Operations"}`;

    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'llama3-8b-8192',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt }
          ],
          temperature: 0.3,
          max_tokens: 500,
          response_format: { type: "json_object" }
        }),
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.statusText}`);
      }

      const data = await response.json();
      const content = data.choices[0]?.message?.content;
      
      if (!content) {
        throw new Error('No response from AI');
      }

      return JSON.parse(content);
    } catch (error) {
      console.error('AI API Error:', error);
      throw new Error('Failed to generate command. Please check your API key and try again.');
    }
  }
}

export const aiService = new AIService();
