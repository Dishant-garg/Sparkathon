require("dotenv").config();

let groq = null;
let gemini = null;

// Initialize Groq client dynamically
async function initGroq() {
  if (!groq) {
    const { default: Groq } = await import("groq-sdk");
    groq = new Groq({
      apiKey: process.env.GROQ_API_KEY,
    });
  }
  return groq;
}

async function initGemini() {
  if (!gemini) {
    const { GoogleGenerativeAI } = await import("@google/generative-ai");
    gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  }
  return gemini;
}

// // Constants for handling large code
// const MAX_CHARS_PER_REQUEST = 6000; // More conservative limit for Groq API
// const MAX_TOKENS_PER_REQUEST = 1500; // More conservative token limit
// const MAX_FILES_TO_PROCESS = 3; // Maximum files to analyze at once
// const MAX_FILE_SIZE = 1000; // Maximum characters per file after summarization

const MAX_CHARS_PER_REQUEST = 3_000_000;   // ~3 million chars (roughly, very generous for 1M tokens)
const MAX_TOKENS_PER_REQUEST = 950_000;    // Keep some buffer under 1M tokens max context
const MAX_FILES_TO_PROCESS = 20;            // You can process more files in one go
const MAX_FILE_SIZE = 100_000;               // Allow files up to 100k chars before summarizing


/**
 * Estimates the size of text in characters and tokens
 * @param {string} text - The text to estimate
 * @returns {object} - Object with character and estimated token counts
 */
function estimateSize(text) {
  const chars = text.length;
  const estimatedTokens = Math.ceil(chars / 4); // Rough estimate: 1 token ≈ 4 chars
  return { chars, estimatedTokens };
}

/**
 * Chunks large code into smaller pieces
 * @param {string} code - The code to chunk
 * @param {number} maxChars - Maximum characters per chunk
 * @returns {Array<string>} - Array of code chunks
 */
function chunkCode(code, maxChars = MAX_CHARS_PER_REQUEST) {
  if (code.length <= maxChars) {
    return [code];
  }

  const chunks = [];
  let startIndex = 0;

  while (startIndex < code.length) {
    let endIndex = startIndex + maxChars;
    
    // If not at the end, try to break at a natural boundary
    if (endIndex < code.length) {
      // Look for line breaks near the end
      const nearEndNewline = code.lastIndexOf('\n', endIndex);
      if (nearEndNewline > startIndex + maxChars * 0.8) {
        endIndex = nearEndNewline + 1;
      }
    }

    chunks.push(code.slice(startIndex, endIndex));
    startIndex = endIndex;
  }

  return chunks;
}

/**
 * Summarizes code to reduce size while preserving important security-relevant parts
 * @param {string} code - The code to summarize
 * @param {string} language - The programming language
 * @param {number} targetSize - Target size in characters
 * @returns {string} - Summarized code
 */
function summarizeCode(code, language = "", targetSize = MAX_FILE_SIZE) {
  const lines = code.split('\n');
  const importantLines = [];
  
  // Keep important security-relevant patterns
  const securityPatterns = [
    /password|secret|key|token|auth|login|encrypt|decrypt|hash|salt/i,
    /sql|query|database|db\./i,
    /eval|exec|system|shell|cmd/i,
    /file|path|upload|download/i,
    /cookie|session|jwt|oauth/i,
    /cors|csrf|xss|injection/i,
    /import|require|include/i,
    /function|def|class|async|await/i,
    /http|https|request|response|api/i,
    /validate|sanitize|escape|filter/i
  ];

  // First pass: collect all important lines
  const securityLines = [];
  const structuralLines = [];
  const contextLines = [];

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    
    // Skip empty lines and simple comments
    if (!trimmed || (trimmed.startsWith('//') && trimmed.length < 50)) {
      return;
    }

    // Always include lines matching security patterns
    if (securityPatterns.some(pattern => pattern.test(line))) {
      securityLines.push({ line, index });
      return;
    }

    // Include structural elements
    if (trimmed.includes('{') || trimmed.includes('}') || 
        trimmed.includes('function') || trimmed.includes('class') ||
        trimmed.includes('def ') || trimmed.includes('async ') ||
        trimmed.includes('export') || trimmed.includes('module.exports')) {
      structuralLines.push({ line, index });
      return;
    }

    // Sample context lines (much less frequently for large files)
    if (lines.length > 100 && index % 20 === 0) {
      contextLines.push({ line, index });
    } else if (lines.length <= 100 && index % 5 === 0) {
      contextLines.push({ line, index });
    }
  });

  // Combine lines with priority: security > structural > context
  let selectedLines = [
    ...securityLines,
    ...structuralLines.slice(0, 20), // Limit structural lines
    ...contextLines.slice(0, 10)     // Limit context lines
  ];

  // Sort by original line index
  selectedLines.sort((a, b) => a.index - b.index);
  
  let result = selectedLines.map(item => item.line).join('\n');
  
  // If still too long, take strategic portions
  if (result.length > targetSize) {
    const lines = result.split('\n');
    const take = Math.floor(targetSize / 100); // Rough estimate of lines we can fit
    
    if (lines.length > take) {
      const firstPart = lines.slice(0, Math.floor(take / 2));
      const lastPart = lines.slice(-Math.floor(take / 2));
      result = firstPart.join('\n') + '\n\n// ... [CODE TRUNCATED] ...\n\n' + lastPart.join('\n');
    }
  }

  return result;
}

/**
 * Generates a prompt for code security analysis.
 * @param {string} codeSnippet - The code to analyze.
 * @param {string} language - The programming language of the code (optional).
 * @returns {string} The formatted prompt.
 */
function generateCodeAnalysisPrompt(codeSnippet, language = "") {
  return `
You are a security analysis expert. Analyze the following code and provide top 10 OWASP potential security vulnerabilities in JSON format. Each vulnerability should have a severity level (HIGH, MEDIUM, LOW).

Return the response in this exact JSON structure:
{
  "vulnerabilities": [
    {
      "title": "string",
      "severity": "string",
      "description": "string",
      "impact": "string",
      "remediation": "string"
    }
  ]
}

Code to analyze:
\`\`\`${language || "text"}
${codeSnippet}
\`\`\`

Provide your response as a valid JSON object only, with no additional text or explanations.`;
}

/**
 * Analyzes a given code snippet for security vulnerabilities.
 * Handles large code by chunking or summarizing as needed.
 * @param {string} codeSnippet - The code to analyze.
 * @param {string} language - The programming language of the code (optional).
 * @returns {Promise<string>} The security analysis report.
 */
async function analyzeCode(codeSnippet, language = "") {
  try {
    const groqClient = await initGroq();
    const { chars, estimatedTokens } = estimateSize(codeSnippet);
    
    console.log(`Code analysis request: ${chars} chars, ~${estimatedTokens} tokens`);
    
    let codeToAnalyze = codeSnippet;
    let wasModified = false;
    
    // If code is too large, try to summarize it first
    if (chars > MAX_CHARS_PER_REQUEST || estimatedTokens > MAX_TOKENS_PER_REQUEST) {
      console.log("Code too large, attempting to summarize...");
      codeToAnalyze = summarizeCode(codeSnippet, language);
      wasModified = true;
      
      const { chars: newChars, estimatedTokens: newTokens } = estimateSize(codeToAnalyze);
      console.log(`After summarization: ${newChars} chars, ~${newTokens} tokens`);
      
      // If still too large after summarization, chunk it
      if (newChars > MAX_CHARS_PER_REQUEST || newTokens > MAX_TOKENS_PER_REQUEST) {
        console.log("Still too large after summarization, chunking...");
        return await analyzeCodeInChunks(codeToAnalyze, language);
      }
    }
    
    const prompt = generateCodeAnalysisPrompt(codeToAnalyze, language);
    
    const response = await groqClient.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: prompt },
      ],
      temperature: 0.1,
      max_tokens: 2048,
    });

    let result = response.choices[0].message.content;
    
    // Add disclaimer if code was modified
    if (wasModified) {
      try {
        const parsed = JSON.parse(result);
        parsed.disclaimer = "Note: Analysis performed on summarized/truncated code due to size limitations. Some vulnerabilities may not be detected.";
        result = JSON.stringify(parsed, null, 2);
      } catch (e) {
        // If parsing fails, just append disclaimer as text
        result += "\n\nNote: Analysis performed on summarized/truncated code due to size limitations.";
      }
    }
    
    return result;
  } catch (error) {
    console.error("Error in analysisService:", error);
    throw error;
  }
}

async function analyzeCodeGemini(codeSnippet, language = "") {
  try {
    console.log("Starting Gemini code analysis...");
    const geminiClient = await initGemini();
    const model = geminiClient.getGenerativeModel({ model: "gemini-2.0-flash" });

    const { chars, estimatedTokens } = estimateSize(codeSnippet);
    console.log(`Code analysis request: ${chars} chars, ~${estimatedTokens} tokens`);

    // Optional: Warn if you're getting close to the 1M token context
    if (estimatedTokens > 950000) {
      console.warn("⚠️ Input is approaching Gemini's context window limit (1M tokens). Consider reducing input size.");
    }

    const prompt = generateCodeAnalysisPrompt(codeSnippet, language);

    // const result = await model.generateContent([
    //   { role: "user", parts: [{ text: prompt }] }
    // ]);
    const result = await model.generateContent({
      contents: [
        {
          parts: [{ text: prompt }]
        }
      ]
    });

    return result.response.text();

  } catch (error) {
    console.error("Error in analyzeCode with Gemini:", error);
    throw error;
  }
}


/**
 * Analyzes code in chunks when it's too large for a single request.
 * @param {string} codeSnippet - The large code to analyze.
 * @param {string} language - The programming language.
 * @returns {Promise<string>} - Combined analysis report.
 */
async function analyzeCodeInChunks(codeSnippet, language = "") {
  const groqClient = await initGroq();
  const chunks = chunkCode(codeSnippet);
  console.log(`Analyzing code in ${chunks.length} chunks`);
  
  const chunkAnalyses = [];
  
  for (let i = 0; i < chunks.length; i++) {
    try {
      console.log(`Analyzing chunk ${i + 1}/${chunks.length}`);
      const prompt = generateCodeAnalysisPrompt(chunks[i], language);
      
      const response = await groqClient.chat.completions.create({
        model: "llama-3.1-8b-instant",
        messages: [
          { role: "system", content: "You are a helpful assistant." },
          { role: "user", content: prompt },
        ],
        temperature: 0.1,
        max_tokens: 2048,
      });
      
      const analysis = response.choices[0].message.content;
      chunkAnalyses.push({ chunk: i + 1, analysis });
      
      // Add delay between requests to avoid rate limiting
      if (i < chunks.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (error) {
      console.error(`Error analyzing chunk ${i + 1}:`, error);
      chunkAnalyses.push({ 
        chunk: i + 1, 
        analysis: `{"vulnerabilities": [], "error": "Failed to analyze chunk ${i + 1}: ${error.message}"}` 
      });
    }
  }
  
  // Combine all analyses
  return combineChunkAnalyses(chunkAnalyses);
}

/**
 * Combines multiple chunk analyses into a single report.
 * @param {Array} chunkAnalyses - Array of chunk analysis results.
 * @returns {string} - Combined analysis report.
 */
function combineChunkAnalyses(chunkAnalyses) {
  const allVulnerabilities = [];
  let hasErrors = false;
  
  chunkAnalyses.forEach(({ chunk, analysis }) => {
    try {
      const parsed = JSON.parse(analysis);
      if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
        // Add chunk info to each vulnerability
        parsed.vulnerabilities.forEach(vuln => {
          vuln.source_chunk = chunk;
          allVulnerabilities.push(vuln);
        });
      }
      if (parsed.error) {
        hasErrors = true;
      }
    } catch (e) {
      console.error(`Failed to parse analysis for chunk ${chunk}:`, e);
      hasErrors = true;
    }
  });
  
  // Remove duplicates based on title and severity
  const uniqueVulnerabilities = [];
  const seen = new Set();
  
  allVulnerabilities.forEach(vuln => {
    const key = `${vuln.title}_${vuln.severity}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueVulnerabilities.push(vuln);
    }
  });
  
  // Sort by severity (HIGH, MEDIUM, LOW)
  const severityOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  uniqueVulnerabilities.sort((a, b) => 
    (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0)
  );
  
  // Take top 10
  const topVulnerabilities = uniqueVulnerabilities.slice(0, 10);
  
  const result = {
    vulnerabilities: topVulnerabilities,
    disclaimer: `Analysis performed on ${chunkAnalyses.length} code chunks. Some context may be lost between chunks.` +
                (hasErrors ? " Some chunks failed to analyze." : "")
  };
  
  return JSON.stringify(result, null, 2);
}

/**
 * Detects programming language based on file extension.
 * @param {string} filePath - The file path.
 * @returns {string} - Detected language.
 */
function detectLanguage(filePath) {
  const extensionMap = {
    js: "JavaScript",
    json: "JSON",
    py: "Python",
    ts: "TypeScript",
    java: "Java",
    cpp: "C++",
    cs: "C#",
    go: "Go",
    php: "PHP",
    rb: "Ruby",
  };

  const ext = filePath.split(".").pop();
  return extensionMap[ext] || "Unknown";
}

/**
 * Generates a dynamic prompt for AI analysis.
 * @param {Array} codeFiles - List of code files (path + content).
 * @param {string} question - User's question.
 * @returns {string} - The formatted prompt.
 */
function generateAnswerCodeQueriesPrompt(codeFiles, question = "") {
  let formattedCode = codeFiles
    .map((file) => {
      const language = detectLanguage(file.path);
      return `### File: ${file.path} (${language})\n\`\`\`${language}\n${file.content}\n\`\`\`\n`;
    })
    .join("\n");

  // TODO: Improvise the prompt
  return `
You are a software analysis expert. Analyze the following codebase consisting of multiple files.

${
  question
    ? `User's question: ${question}`
    : "Provide an overview of what this code does."
}

Codebase:
${formattedCode}

Respond in structured JSON format:
{
  "summary": "Brief summary of the entire codebase",
  "key_features": ["Feature 1", "Feature 2", "Feature 3"],
  "potential_issues": ["Issue 1", "Issue 2"],
  "best_practices": ["Suggestion 1", "Suggestion 2"]
}
If security concerns are relevant, include them under "potential_issues". If the user asks a specific question, answer it concisely.
  `;
}

/**
 * Analyzes multiple code files using Groq API.
 * Handles large codebases by summarizing or chunking as needed.
 * @param {Array} codeFiles - List of code files.
 * @param {string} question - User's question.
 * @returns {Promise<string>} - The analysis report.
 */
async function getQueryAboutCode(codeFiles, question = "") {
  try {
    const groqClient = await initGroq();
    // Calculate total size of all code files
    const totalContent = codeFiles.map(f => f.content).join('\n');
    const { chars, estimatedTokens } = estimateSize(totalContent);
    
    console.log(`Code query request: ${chars} chars, ~${estimatedTokens} tokens across ${codeFiles.length} files`);
    
    let processedFiles = codeFiles;
    let wasModified = false;
    
    // For extremely large codebases (>1M chars), be very aggressive
    if (chars > 1000000) {
      console.log("Extremely large codebase detected, using aggressive filtering...");
      
      // First, filter files by relevance to the question
      let relevantFiles = codeFiles;
      
      if (question) {
        const questionWords = question.toLowerCase().split(/\s+/).filter(w => w.length > 2);
        relevantFiles = codeFiles
          .map(file => {
            let score = 0;
            const fileName = file.path.toLowerCase();
            const fileContent = file.content.toLowerCase();
            
            // Score based on filename relevance
            questionWords.forEach(word => {
              if (fileName.includes(word)) score += 10;
              if (fileContent.includes(word)) score += 1;
            });
            
            // Boost score for important files
            if (fileName.includes('main') || fileName.includes('index') || fileName.includes('app')) score += 5;
            if (fileName.includes('controller') || fileName.includes('service') || fileName.includes('model')) score += 3;
            if (fileName.includes('route') || fileName.includes('api')) score += 3;
            
            return { ...file, relevanceScore: score };
          })
          .sort((a, b) => b.relevanceScore - a.relevanceScore)
          .slice(0, 5); // Take only top 5 most relevant files
      } else {
        // No specific question, take the most important files
        relevantFiles = codeFiles
          .filter(file => {
            const fileName = file.path.toLowerCase();
            return fileName.includes('main') || fileName.includes('index') || 
                   fileName.includes('app') || fileName.includes('controller') ||
                   fileName.includes('service') || fileName.includes('model') ||
                   fileName.includes('route') || fileName.includes('api');
          })
          .slice(0, 3); // Take only 3 most important files
      }
      
      processedFiles = relevantFiles;
      wasModified = true;
      console.log(`Filtered down to ${processedFiles.length} most relevant files`);
    }
    
    // Always summarize files that are too large
    processedFiles = processedFiles.map(file => {
      if (file.content.length > MAX_FILE_SIZE) {
        return {
          ...file,
          content: summarizeCode(file.content, detectLanguage(file.path), MAX_FILE_SIZE)
        };
      }
      return file;
    });
    
    // Final size check - limit to MAX_FILES_TO_PROCESS files
    if (processedFiles.length > MAX_FILES_TO_PROCESS) {
      processedFiles = processedFiles.slice(0, MAX_FILES_TO_PROCESS);
      wasModified = true;
      console.log(`Limited to ${MAX_FILES_TO_PROCESS} files for processing`);
    }
    
    // Check final size
    const finalContent = processedFiles.map(f => f.content).join('\n');
    const { chars: finalChars } = estimateSize(finalContent);
    console.log(`Final content size: ${finalChars} chars across ${processedFiles.length} files`);
    
    // If still too large, use aggressive summarization
    if (finalChars > MAX_CHARS_PER_REQUEST * 2) {
      console.log('Content still too large, applying aggressive summarization...');
      processedFiles = processedFiles.map(file => ({
        ...file,
        content: summarizeCode(file.content, detectLanguage(file.path), MAX_FILE_SIZE / 2)
      }));
      
      const finalContent = processedFiles.map(f => f.content).join('\n');
      const { chars: finalCharsAfterSummary } = estimateSize(finalContent);
      console.log(`After aggressive summarization: ${finalCharsAfterSummary} chars`);
      
      if (finalCharsAfterSummary > MAX_CHARS_PER_REQUEST * 3) {
        throw new Error(`Codebase is still too large after optimization (${finalCharsAfterSummary} chars). Please ask about specific files or use more targeted queries.`);
      }
    }
    
    const prompt = generateAnswerCodeQueriesPrompt(processedFiles, question);
    
    // Add timeout to the request
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout')), 30000); // 30 second timeout
    });
    
    const analysisPromise = groqClient.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        { role: "system", content: "You are a coding assistant." },
        { role: "user", content: prompt },
      ],
      temperature: 0.1,
      max_tokens: 2048,
    });

    const response = await Promise.race([analysisPromise, timeoutPromise]);
    let result = response.choices[0].message.content;
    
    // Add disclaimer if code was modified
    if (wasModified) {
      try {
        const parsed = JSON.parse(result);
        parsed.disclaimer = `Note: Analysis performed on ${processedFiles.length} out of ${codeFiles.length} files (${Math.round(finalChars/chars*100)}% of original content). Files were filtered and summarized due to size limitations.`;
        result = JSON.stringify(parsed, null, 2);
      } catch (e) {
        // If parsing fails, just append disclaimer as text
        result += `\n\nNote: Analysis performed on ${processedFiles.length} out of ${codeFiles.length} files. Content was significantly reduced due to size limitations.`;
      }
    }
    
    return result;
  } catch (error) {
    console.error("Error in analysisService:", error);
    
    // Handle specific Groq API errors
    if (error.status === 413 || error.message.includes('413') || error.message.includes('too large')) {
      throw new Error('Code is too large for analysis even after optimization. Please try asking about specific files or use more targeted queries.');
    }
    
    if (error.message.includes('timeout')) {
      throw new Error('Analysis request timed out. The codebase might be too complex. Please try with more specific queries.');
    }
    
    throw error;
  }
}


async function getQueryAboutCodeGemini(codeFiles, question = "") {
  try {
    console.log("Starting Gemini code analysis...");
    const geminiClient = await initGemini();
    const model = geminiClient.getGenerativeModel({ model: "gemini-2.0-flash" });

    // Combine all file contents for size estimation
    const totalContent = codeFiles.map(f => f.content).join('\n');
    const { chars, estimatedTokens } = estimateSize(totalContent);

    console.log(`Code query request: ${chars} chars, ~${estimatedTokens} tokens across ${codeFiles.length} files`);

    let processedFiles = codeFiles;
    let wasModified = false;

    // Aggressive filtering for extremely large codebases (>1M chars)
    if (chars > 1_000_000) {
      console.log("Extremely large codebase detected, using aggressive filtering...");

      let relevantFiles = codeFiles;

      if (question) {
        const questionWords = question.toLowerCase().split(/\s+/).filter(w => w.length > 2);
        relevantFiles = codeFiles
          .map(file => {
            let score = 0;
            const fileName = file.path.toLowerCase();
            const fileContent = file.content.toLowerCase();

            questionWords.forEach(word => {
              if (fileName.includes(word)) score += 10;
              if (fileContent.includes(word)) score += 1;
            });

            if (fileName.includes('main') || fileName.includes('index') || fileName.includes('app')) score += 5;
            if (fileName.includes('controller') || fileName.includes('service') || fileName.includes('model')) score += 3;
            if (fileName.includes('route') || fileName.includes('api')) score += 3;

            return { ...file, relevanceScore: score };
          })
          .sort((a, b) => b.relevanceScore - a.relevanceScore)
          .slice(0, 5);
      } else {
        relevantFiles = codeFiles
          .filter(file => {
            const fileName = file.path.toLowerCase();
            return ['main', 'index', 'app', 'controller', 'service', 'model', 'route', 'api'].some(key => fileName.includes(key));
          })
          .slice(0, 3);
      }

      processedFiles = relevantFiles;
      wasModified = true;
      console.log(`Filtered down to ${processedFiles.length} most relevant files`);
    }

    // Summarize large files (if > MAX_FILE_SIZE)
    processedFiles = processedFiles.map(file => {
      if (file.content.length > MAX_FILE_SIZE) {
        return {
          ...file,
          content: summarizeCode(file.content, detectLanguage(file.path), MAX_FILE_SIZE),
        };
      }
      return file;
    });

    // Limit number of files to process
    if (processedFiles.length > MAX_FILES_TO_PROCESS) {
      processedFiles = processedFiles.slice(0, MAX_FILES_TO_PROCESS);
      wasModified = true;
      console.log(`Limited to ${MAX_FILES_TO_PROCESS} files for processing`);
    }

    // Check final content size
    let finalContent = processedFiles.map(f => f.content).join('\n');
    let { chars: finalChars, estimatedTokens: finalTokens } = estimateSize(finalContent);
    console.log(`Final content size: ${finalChars} chars, ~${finalTokens} tokens across ${processedFiles.length} files`);

    // If still too large for the Gemini 1M token limit, apply aggressive summarization
    if (finalTokens > 950_000) {
      console.log('Content still too large, applying aggressive summarization...');
      processedFiles = processedFiles.map(file => ({
        ...file,
        content: summarizeCode(file.content, detectLanguage(file.path), MAX_FILE_SIZE / 2),
      }));

      finalContent = processedFiles.map(f => f.content).join('\n');
      ({ chars: finalChars, estimatedTokens: finalTokens } = estimateSize(finalContent));
      console.log(`After aggressive summarization: ${finalChars} chars, ~${finalTokens} tokens`);

      if (finalTokens > 1_000_000) {
        throw new Error(`Codebase is still too large after optimization (${finalTokens} tokens). Please ask about specific files or use more targeted queries.`);
      }
      wasModified = true;
    }

    const prompt = generateAnswerCodeQueriesPrompt(processedFiles, question);

    // Timeout helper to avoid hanging
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout')), 60000); // 60 seconds timeout
    });

    // const analysisPromise = model.generateContent([
    //   { role: "user", parts: [{ text: prompt }] }
    // ]);
    const analysisPromise = model.generateContent({
      contents: [
        {
          parts: [{ text: prompt }]
        }
      ]
    });


    const result = await Promise.race([analysisPromise, timeoutPromise]);

    let output = result.response.text();

    if (wasModified) {
      try {
        const parsed = JSON.parse(output);
        parsed.disclaimer = `Note: Analysis performed on ${processedFiles.length} out of ${codeFiles.length} files (${Math.round(finalChars / chars * 100)}% of original content). Files were filtered and summarized due to size limitations.`;
        output = JSON.stringify(parsed, null, 2);
      } catch {
        output += `\n\nNote: Analysis performed on ${processedFiles.length} out of ${codeFiles.length} files. Content was reduced due to size limitations.`;
      }
    }

    return output;
  } catch (error) {
    console.error("Error in getQueryAboutCode with Gemini:", error);

    if (error.message.includes('timeout')) {
      throw new Error('Analysis request timed out. Try more targeted queries.');
    }

    throw error;
  }
}
module.exports = { analyzeCode, getQueryAboutCode, 
                  analyzeCodeGemini, getQueryAboutCodeGemini };
