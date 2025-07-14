import { languageColors } from "./constant";

export const getLanguageColor = (language: string): string => {
  return languageColors[language] || "#CCCCCC";
};
