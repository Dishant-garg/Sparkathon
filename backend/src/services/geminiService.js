const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Groq } = require('groq-sdk');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

// Initialize AI providers
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'your-gemini-api-key');
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || 'your-groq-api-key',
});

// Storage directory for embeddings and analysis
const STORAGE_DIR = path.join(__dirname, '../../data');
const EMBEDDINGS_DIR = path.join(STORAGE_DIR, 'embeddings');
const ANALYSIS_DIR = path.join(STORAGE_DIR, 'analysis');

// Ensure directories exist
fs.ensureDirSync(STORAGE_DIR);
fs.ensureDirSync(EMBEDDINGS_DIR);
fs.ensureDirSync(ANALYSIS_DIR);

/**
 * Initialize AI models
 */
const getGeminiModel = () => {
  return genAI.getGenerativeModel({ 
    model: "gemini-1.5-pro",
    generationConfig: {
      maxOutputTokens: 4096, // Reduced for faster responses
      temperature: 0.3,
      topP: 0.8,
      topK: 40,
    },
  });
};

const getGroqModel = () => {
  return groq.chat.completions;
};

/**
 * Create repository fingerprint for caching
 * @param {Array} files - Repository files
 * @returns {string} - Repository fingerprint
 */
const createRepoFingerprint = (files) => {
  const fileHashes = files.map(file => {
    const content = file.content || '';
    return crypto.createHash('md5').update(`${file.path}:${content.length}`).digest('hex');
  }).sort();
  
  return crypto.createHash('md5').update(fileHashes.join('')).digest('hex');
};

/**
 * Create embeddings for repository files with local caching
 * @param {string} repoId - Repository identifier
 * @param {Array} files - Repository files with content
 * @returns {Promise<Object>} - Embeddings data
 */
const createEmbeddings = async (repoId, files) => {
  try {
    console.log(`Creating embeddings for repo: ${repoId}`);
    
    // Create repository fingerprint
    const repoFingerprint = createRepoFingerprint(files);
    const cacheKey = `${repoId}_${repoFingerprint}`;
    
    // Check if embeddings already exist for this fingerprint
    const existingEmbeddings = await loadEmbeddings(cacheKey);
    if (existingEmbeddings) {
      console.log(`✅ Using cached embeddings for ${repoId}`);
      return existingEmbeddings;
    }
    
    const geminiModel = getGeminiModel();
    const embeddings = {};
    
    // Process files in smaller batches for better performance
    const batchSize = 3; // Reduced batch size
    for (let i = 0; i < files.length; i += batchSize) {
      const batch = files.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (file) => {
        try {
          // Chunk large files into smaller pieces
          const content = file.content || '';
          const chunks = chunkContent(content, 1500); // Reduced chunk size
          
          const fileEmbeddings = [];
          
          for (let j = 0; j < chunks.length; j++) {
            const chunk = chunks[j];
            
            // Create a compact summary for embedding
            const chunkSummary = {
              path: file.path,
              chunk: j + 1,
              total: chunks.length,
              content: chunk.substring(0, 1000), // Limit content size
              size: chunk.length
            };
            
            // Generate embedding using Gemini
            const result = await geminiModel.embedContent({
              content: {
                parts: [{
                  text: JSON.stringify(chunkSummary)
                }]
              }
            });
            
            const embedding = await result.embedding;
            
            fileEmbeddings.push({
              chunkIndex: j,
              embedding: embedding.values,
              summary: chunkSummary
            });
          }
          
          return {
            path: file.path,
            chunks: fileEmbeddings,
            totalChunks: chunks.length
          };
        } catch (error) {
          console.error(`Error creating embedding for ${file.path}:`, error.message);
          return null;
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      batchResults.forEach(result => {
        if (result) {
          embeddings[result.path] = result;
        }
      });
      
      // Add delay between batches
      if (i + batchSize < files.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    // Save embeddings to local storage with fingerprint
    const embeddingsPath = path.join(EMBEDDINGS_DIR, `${cacheKey}.json`);
    await fs.writeJson(embeddingsPath, {
      repoId,
      fingerprint: repoFingerprint,
      createdAt: new Date().toISOString(),
      embeddings,
      fileCount: Object.keys(embeddings).length,
      totalChunks: Object.values(embeddings).reduce((sum, file) => sum + file.totalChunks, 0)
    });
    
    console.log(`✅ Created embeddings for ${Object.keys(embeddings).length} files with ${Object.values(embeddings).reduce((sum, file) => sum + file.totalChunks, 0)} chunks`);
    return embeddings;
    
  } catch (error) {
    console.error('Error creating embeddings:', error);
    throw new Error(`Failed to create embeddings: ${error.message}`);
  }
};

/**
 * Load embeddings from local storage
 * @param {string} cacheKey - Cache key (repoId_fingerprint)
 * @returns {Promise<Object|null>} - Embeddings data or null
 */
const loadEmbeddings = async (cacheKey) => {
  try {
    const embeddingsPath = path.join(EMBEDDINGS_DIR, `${cacheKey}.json`);
    
    if (await fs.pathExists(embeddingsPath)) {
      const data = await fs.readJson(embeddingsPath);
      console.log(`📁 Loaded embeddings for ${data.fileCount} files from cache`);
      return data.embeddings;
    }
    
    return null;
  } catch (error) {
    console.error('Error loading embeddings:', error);
    return null;
  }
};

/**
 * Find relevant files based on user query with optimized search
 * @param {string} query - User's question
 * @param {Object} embeddings - File embeddings
 * @returns {Promise<Array>} - Relevant files with scores
 */
const findRelevantFiles = async (query, embeddings) => {
  try {
    const geminiModel = getGeminiModel();
    
    // Create query embedding
    const queryResult = await geminiModel.embedContent({
      content: {
        parts: [{
          text: query
        }]
      }
    });
    
    const queryEmbedding = await queryResult.embedding;
    
    // Calculate similarity scores for all chunks
    const similarities = [];
    
    for (const [filePath, fileData] of Object.entries(embeddings)) {
      for (const chunk of fileData.chunks) {
        const similarity = calculateCosineSimilarity(
          queryEmbedding.values,
          chunk.embedding
        );
        
        similarities.push({
          path: filePath,
          chunkIndex: chunk.chunkIndex,
          score: similarity,
          summary: chunk.summary
        });
      }
    }
    
    // Sort by similarity score and return top results
    return similarities
      .sort((a, b) => b.score - a.score)
      .slice(0, 5); // Reduced to top 5 for faster processing
      
  } catch (error) {
    console.error('Error finding relevant files:', error);
    throw new Error(`Failed to find relevant files: ${error.message}`);
  }
};

/**
 * Calculate cosine similarity between two vectors
 * @param {Array} vecA - First vector
 * @param {Array} vecB - Second vector
 * @returns {number} - Similarity score
 */
const calculateCosineSimilarity = (vecA, vecB) => {
  if (vecA.length !== vecB.length) {
    return 0;
  }
  
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  
  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }
  
  normA = Math.sqrt(normA);
  normB = Math.sqrt(normB);
  
  if (normA === 0 || normB === 0) {
    return 0;
  }
  
  return dotProduct / (normA * normB);
};

/**
 * Analyze code with optimized context
 * @param {string} query - User's question
 * @param {Array} relevantFiles - Relevant files with content
 * @returns {Promise<string>} - AI analysis response
 */
const analyzeCode = async (query, relevantFiles, provider = 'gemini') => {
  try {
    // Prepare compact context from relevant files
    const context = relevantFiles.map(file => {
      const content = file.content.substring(0, 1000); // Limit content size
      return `File: ${file.path}\nContent:\n${content}...`;
    }).join('\n\n');
    
    // Create focused prompt for code analysis
    const prompt = `
Analyze the following code files and answer the user's question.

User Question: ${query}

Relevant Files:
${context}

Provide a concise analysis focusing on:
1. Security vulnerabilities
2. Code quality issues
3. Specific recommendations

Keep response under 1000 words.
`;

    if (provider === 'groq') {
      const groqModel = getGroqModel();
      const completion = await groqModel.create({
        messages: [
          {
            role: "system",
            content: "You are an expert security analyst and code reviewer."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        model: "llama3-8b-8192",
        temperature: 0.3,
        max_tokens: 2048, // Reduced token limit
      });
      
      return completion.choices[0]?.message?.content || 'No response generated';
    } else {
      // Default to Gemini
      const geminiModel = getGeminiModel();
      const result = await geminiModel.generateContent(prompt);
      const response = await result.response;
      
      return response.text();
    }
    
  } catch (error) {
    console.error('Error analyzing code:', error);
    throw new Error(`Failed to analyze code: ${error.message}`);
  }
};

/**
 * Chunk large content into smaller pieces
 * @param {string} content - File content
 * @param {number} maxChunkSize - Maximum chunk size in characters
 * @returns {Array} - Array of chunks
 */
const chunkContent = (content, maxChunkSize = 1500) => {
  const chunks = [];
  let currentChunk = '';
  
  const lines = content.split('\n');
  
  for (const line of lines) {
    if (currentChunk.length + line.length + 1 > maxChunkSize) {
      if (currentChunk) {
        chunks.push(currentChunk.trim());
        currentChunk = '';
      }
    }
    currentChunk += line + '\n';
  }
  
  if (currentChunk.trim()) {
    chunks.push(currentChunk.trim());
  }
  
  return chunks;
};

/**
 * Process large repositories with optimized filtering
 * @param {Array} files - Repository files
 * @param {number} maxFiles - Maximum files to process
 * @param {number} maxFileSize - Maximum file size in bytes
 * @returns {Array} - Filtered and chunked files
 */
const processLargeRepository = (files, maxFiles = 30, maxFileSize = 30000) => {
  try {
    console.log(`Processing ${files.length} files for large repository`);
    
    // Filter files by size and type
    const allowedExtensions = ['.js', '.ts', '.py', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c', '.jsx', '.tsx', '.vue', '.swift', '.kt', '.html', '.css', '.scss', '.json', '.xml', '.yaml', '.yml'];
    
    const filteredFiles = files
      .filter(file => {
        const ext = path.extname(file.path || file.name || '').toLowerCase();
        return allowedExtensions.includes(ext) && 
               (file.size || 0) <= maxFileSize &&
               !file.path?.includes('node_modules') &&
               !file.path?.includes('.git') &&
               !file.path?.includes('dist') &&
               !file.path?.includes('build') &&
               !file.path?.includes('coverage');
      })
      .slice(0, maxFiles);
    
    console.log(`✅ Filtered to ${filteredFiles.length} relevant files`);
    return filteredFiles;
    
  } catch (error) {
    console.error('Error processing large repository:', error);
    throw new Error(`Failed to process large repository: ${error.message}`);
  }
};

/**
 * Main chatbot function with optimized caching
 * @param {string} repoId - Repository identifier
 * @param {string} query - User's question
 * @param {Array} files - Repository files (optional, will load from embeddings if not provided)
 * @returns {Promise<Object>} - Chatbot response
 */
const chatWithRepository = async (repoId, query, files = null, provider = 'gemini') => {
  try {
    console.log(`🤖 Chatbot query for repo ${repoId}: ${query} (using ${provider})`);
    
    // Create repository fingerprint
    const repoFingerprint = files ? createRepoFingerprint(files) : null;
    const cacheKey = repoFingerprint ? `${repoId}_${repoFingerprint}` : repoId;
    
    // Load or create embeddings
    let embeddings = await loadEmbeddings(cacheKey);
    
    if (!embeddings) {
      if (!files) {
        throw new Error('No files provided and no embeddings found');
      }
      
      // Process large repositories
      const processedFiles = processLargeRepository(files);
      embeddings = await createEmbeddings(repoId, processedFiles);
    }
    
    // Find relevant files based on query
    const relevantFiles = await findRelevantFiles(query, embeddings);
    
    if (relevantFiles.length === 0) {
      return {
        answer: "I couldn't find any relevant files for your question. Please try rephrasing your query or ask about specific aspects of the codebase.",
        relevantFiles: [],
        confidence: 0,
        provider
      };
    }
    
    // Get full content for relevant chunks
    const filesWithContent = relevantFiles.map(file => {
      const embedding = embeddings[file.path];
      const chunk = embedding.chunks[file.chunkIndex];
      return {
        path: file.path,
        chunkIndex: file.chunkIndex,
        content: chunk.summary.content,
        score: file.score
      };
    });
    
    // Analyze code with selected provider
    const analysis = await analyzeCode(query, filesWithContent, provider);
    
    return {
      answer: analysis,
      relevantFiles: relevantFiles.map(f => ({ path: f.path, score: f.score })),
      confidence: relevantFiles[0]?.score || 0,
      provider
    };
    
  } catch (error) {
    console.error('Error in chatbot:', error);
    throw new Error(`Chatbot error: ${error.message}`);
  }
};

/**
 * Get repository analysis cache
 * @param {string} repoId - Repository identifier
 * @returns {Promise<Object|null>} - Cached analysis or null
 */
const getAnalysisCache = async (repoId) => {
  try {
    const cachePath = path.join(ANALYSIS_DIR, `${repoId}.json`);
    
    if (await fs.pathExists(cachePath)) {
      const data = await fs.readJson(cachePath);
      const cacheAge = Date.now() - new Date(data.timestamp).getTime();
      
      // Cache expires after 24 hours
      if (cacheAge < 24 * 60 * 60 * 1000) {
        return data.analysis;
      }
    }
    
    return null;
  } catch (error) {
    console.error('Error getting analysis cache:', error);
    return null;
  }
};

/**
 * Save analysis cache
 * @param {string} repoId - Repository identifier
 * @param {Object} analysis - Analysis data
 */
const saveAnalysisCache = async (repoId, analysis) => {
  try {
    const cachePath = path.join(ANALYSIS_DIR, `${repoId}.json`);
    await fs.writeJson(cachePath, {
      repoId,
      timestamp: new Date().toISOString(),
      analysis
    });
  } catch (error) {
    console.error('Error saving analysis cache:', error);
  }
};

module.exports = {
  createEmbeddings,
  loadEmbeddings,
  chatWithRepository,
  processLargeRepository,
  getAnalysisCache,
  saveAnalysisCache,
  findRelevantFiles,
  analyzeCode,
  chunkContent,
  createRepoFingerprint
}; 