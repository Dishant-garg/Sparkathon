import { languageColors } from "./constant";

export const getLanguageColor = (language: string | null | undefined): string => {
  if (!language) return "#6B7280";
  
  const normalizedLanguage = language.toLowerCase().trim();
  
  // Try exact match first
  if (languageColors[language]) {
    return languageColors[language];
  }
  
  // Try normalized match
  if (languageColors[normalizedLanguage]) {
    return languageColors[normalizedLanguage];
  }
  
  // Try case-insensitive match
  const match = Object.keys(languageColors).find(
    key => key.toLowerCase() === normalizedLanguage
  );
  
  if (match) {
    return languageColors[match];
  }
  
  // Return default color for unknown languages
  return "#6B7280";
};
