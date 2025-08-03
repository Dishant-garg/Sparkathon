const Groq = require("groq-sdk");
const { GoogleGenerativeAI } = require("@google/generative-ai");
require("dotenv").config();

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

exports.generateFlowChart = async (text, provider = "groq") => {
  const prompt = `Based on these text, generate a Mermaid.js flowchart diagram showing the system architecture:
${text}

Include:
1. Main components and their relationships
2. Data flow
3. External services
4. Key processes

Respond only with the Mermaid.js diagram code, no explanations.`;

  try {
    if (provider === "groq") {
      const response = await groq.chat.completions.create({
        model: "llama-3.1-70b-versatile",
        messages: [
          {
            role: "system",
            content:
              "You are a system architecture expert that creates Mermaid.js flowcharts.",
          },
          { role: "user", content: prompt },
        ],
        temperature: 0.3,
        max_tokens: 1000,
      });

      return response.choices[0].message.content.trim();
    } else if (provider === "gemini") {
      const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
      const result = await model.generateContent(prompt);
      const response = await result.response;
      return response.text().trim();
    } else {
      throw new Error("Invalid provider. Use 'groq' or 'gemini'.");
    }
  } catch (error) {
    console.error(`${provider.toUpperCase()} API error:`, error);
    throw new Error(`Failed to generate Mermaid.js diagram using ${provider}`);
  }
};
