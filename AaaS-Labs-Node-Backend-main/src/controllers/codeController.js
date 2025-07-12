const analysisService = require("../services/analysisService");

exports.analyzeCode = async (req, res) => {
  try {
    const { code, language } = req.body;
    if (!code) {
      return res.status(400).json({ error: "Code is required" });
    }
    const analysisReport = await analysisService.analyzeCode(code, language);
    res.json({ analysis: analysisReport });
  } catch (error) {
    console.error("Error analyzing code:", error);
    res.status(500).json({ error: "Failed to analyze code" });
  }
};

exports.getQueryAboutCode = async (req, res) => {
  try {
    const { code, question } = req.body;

    if (!Array.isArray(code) || code.length === 0) {
      return res
        .status(400)
        .json({ error: "Code files are required in an array." });
    }

    const analysisReport = await analysisService.getQueryAboutCode(code, question);
    res.json({ response: analysisReport });
  } catch (error) {
    console.error("Error answering code queries:", error);
    res.status(500).json({ error: "Failed to answer code queries" });
  }
};
