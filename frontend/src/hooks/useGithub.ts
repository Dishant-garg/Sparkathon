import { useState, useCallback } from "react";
import { BACKEND_URL } from "@/lib/constant";
import { Repository } from "@/types";
import useAuth from "./useAuth";

interface ApiResponse {
  success?: boolean;
  count?: number;
  data?: Repository[];
  message?: string;
  error?: string;
}

const useGitHub = () => {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [repoFiles, setRepoFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Remove duplicate repositories based on name and owner
  const removeDuplicateRepos = (repositories: Repository[]): Repository[] => {
    const seen = new Set();
    return repositories.filter((repo) => {
      const key = `${repo.owner}/${repo.name}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  };

  // Sort repositories by last updated date (newest first)
  const sortRepositories = (repositories: Repository[]): Repository[] => {
    return repositories.sort((a, b) => {
      const dateA = a.lastUpdated ? new Date(a.lastUpdated).getTime() : 0;
      const dateB = b.lastUpdated ? new Date(b.lastUpdated).getTime() : 0;
      return dateB - dateA;
    });
  };

  const fetchRepositories = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/api/github/repos`, {
        credentials: "include",
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        const errorData: ApiResponse = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result: ApiResponse = await response.json();
      // Backend returns { success: true, count: number, data: repos[] }
      const rawRepos = result.data || []; // Handle both formats
      
      // Remove duplicates and sort
      const uniqueRepos = removeDuplicateRepos(rawRepos);
      const sortedRepos = sortRepositories(uniqueRepos);
      
      setRepos(sortedRepos);
      
      // Store repository names for caching
      const repoNameList = sortedRepos.map((repo: Repository) => repo.name);
      localStorage.setItem("repos", JSON.stringify(repoNameList));
      
          } catch (err: unknown) {
        console.error("Failed to fetch repositories:", err);
        const errorMessage = err instanceof Error ? err.message : "Failed to fetch repositories";
        setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, []);

  const { user } = useAuth();
  
  const fetchRepositoryContents = useCallback(async (repo: string) => {
    const owner = user?.username;

    if (!owner) {
      setError("User information not available");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `${BACKEND_URL}/api/github/repo/${owner}/${repo}`,
        {
          credentials: "include",
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      const repoFiles = await response.json();
      setRepoFiles(repoFiles);
          } catch (err: unknown) {
        console.error("Failed to fetch repository contents:", err);
        const errorMessage = err instanceof Error ? err.message : "Failed to fetch repository contents";
        setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, []);

  // Clear error state
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    repos,
    repoFiles,
    loading,
    error,
    fetchRepositories,
    fetchRepositoryContents,
    clearError,
  };
};

export default useGitHub;
