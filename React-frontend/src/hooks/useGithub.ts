import { useState, useCallback } from "react";
import { BACKEND_URL } from "@/lib/constant";
import { Repository } from "@/types";
import useAuth from "./useAuth";

const useGitHub = () => {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [repoFiles, setRepoFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchRepositories = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/api/github/repos`, {
        credentials: "include",
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      // Backend returns { success: true, count: number, data: repos[] }
      const repos = result.data || result; // Handle both formats
      setRepos(repos);
      const repoNameList = repos.map((repo: any) => repo.name);
      localStorage.setItem("repos", JSON.stringify(repoNameList));
    } catch (err: any) {
      console.error("Failed to fetch repositories:", err);
      setError(err.message || "Failed to fetch repositories");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchRepositoryContents = useCallback(async (repo: string) => {
    const { user } = useAuth();
    const owner = user?.username;

    setLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `${BACKEND_URL}/api/github/repo/${owner}/${repo}`,
        {
          credentials: "include",
        }
      );
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      const repoFiles = await response.json();
      setRepoFiles(repoFiles);
    } catch (err: any) {
      console.error("Failed to fetch repository contents:", err);
      setError(err.message || "Failed to fetch repository contents");
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    repos,
    repoFiles,
    loading,
    error,
    fetchRepositories,
    fetchRepositoryContents,
  };
};

export default useGitHub;
