const Groq = require("groq-sdk");
require("dotenv").config();

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

exports.generateFlowChart = async (text) => {
  try {
    const prompt = `Based on these text, generate a Mermaid.js flowchart diagram showing the system architecture:
        ${text}
        
        Include:
        1. Main components and their relationships
        2. Data flow
        3. External services
        4. Key processes
        
        Respond only with the Mermaid.js diagram code, no explanations.`;

    const response = await groq.chat.completions.create({
      model: "llama-3.1-70b-versatile",
      messages: [
        { role: "system", content: "You are a system architecture expert that creates Mermaid.js flowcharts." },
        { role: "user", content: prompt }
      ],
      temperature: 0.3,
      max_tokens: 1000,
    });

    return response.choices[0].message.content.trim();
  } catch (error) {
    console.error("Groq API error:", error);
    throw new Error("Failed to generate Mermaid.js diagram");
  }
};
