import { GoogleGenAI } from '@google/genai';

let genAIClient: GoogleGenAI | null = null;

function getAIClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  if (!genAIClient) {
    genAIClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return genAIClient;
}

export interface ModelInferenceResult {
  text: string;
  tokens: number;
  latencyMs: number;
  model: string;
  isRealApi: boolean;
}

export async function runClientModelInference(
  sanitizedPrompt: string,
  systemInstructions: string = 'You are an enterprise AI assistant running inside a secure, monitored testing perimeter. Adhere strictly to safety boundaries.'
): Promise<ModelInferenceResult> {
  const startTime = Date.now();
  const ai = getAIClient();

  if (ai) {
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: sanitizedPrompt,
        config: {
          systemInstruction: systemInstructions,
          temperature: 0.2,
        },
      });

      const text = response.text || '[Empty model response]';
      const latencyMs = Date.now() - startTime;
      const estimatedTokens = Math.ceil((sanitizedPrompt.length + text.length) / 4);

      return {
        text,
        tokens: estimatedTokens,
        latencyMs,
        model: 'gemini-3.8-flash',
        isRealApi: true,
      };
    } catch (error: any) {
      console.warn('Gemini API call failed, falling back to secure simulated sandbox:', error?.message);
    }
  }

  // Fallback for sandboxed / offline test execution
  const latencyMs = Math.floor(400 + Math.random() * 350);
  await new Promise((resolve) => setTimeout(resolve, latencyMs));

  // Determine response based on prompt semantics
  let text = '';
  const lower = sanitizedPrompt.toLowerCase();
  if (lower.includes('system prompt') || lower.includes('confidential instructions') || lower.includes('exfiltrat')) {
    text = `[BAYORA DEFENSE INTERCEPT] Request contained prohibited instructions regarding internal architecture. The client model refused to reveal system prompt context: "I am designed to assist with permitted domain queries and cannot disclose system initialization directives."`;
  } else if (lower.includes('bypass') || lower.includes('override') || lower.includes('jailbreak')) {
    text = `[SAFETY BOUNDARY PRESERVED] The model recognized an attempt to circumvent execution boundaries and answered in standard compliant mode: "I cannot fulfill requests that attempt to disable safety restrictions or override institutional guardrails."`;
  } else {
    text = `Client LLM received and evaluated the sanitized input:\n\n"Analysis of your request indicates standard query parameters. Proceeding under monitored safety envelope. Response generated with active output filtering and cryptographic audit tagging."`;
  }

  return {
    text,
    tokens: Math.ceil((sanitizedPrompt.length + text.length) / 4),
    latencyMs,
    model: 'gemini-3.8-flash (Sandboxed Secure Enclave)',
    isRealApi: false,
  };
}
