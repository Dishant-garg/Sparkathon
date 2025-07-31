import useGitHub from "@/hooks/useGithub";
import { useEffect, useMemo, useState } from "react";
import { RepositoryHeader } from "@/components/dashboard/repository/RepositoryHeader";
import { RepositoryCard } from "@/components/dashboard/repository/RepositoryCard";
import { RepositoryLoader } from "@/components/dashboard/repository/RepositoryLoader";
import { RepositoryError } from "@/components/dashboard/repository/RepositoryError";

const RepositoryList = () => {
  const { repos, fetchRepositories, loading, error, clearError } = useGitHub();
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    fetchRepositories();
  }, [fetchRepositories]);

  // Clear error when search query changes
  useEffect(() => {
    if (error) {
      clearError();
    }
  }, [searchQuery, clearError]);

  const filteredRepos = useMemo(() => {
    if (!searchQuery.trim()) return repos;

    const query = searchQuery.toLowerCase().trim();
    return repos.filter((repo) => {
      return (
        repo.name.toLowerCase().includes(query) ||
        (repo.language && repo.language.toLowerCase().includes(query)) ||
        (repo.private ? "private" : "public").includes(query) ||
        (repo.description && repo.description.toLowerCase().includes(query))
      );
    });
  }, [repos, searchQuery]);

  const handleRetry = () => {
    clearError();
    fetchRepositories();
  };

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  if (error) {
    return <RepositoryError error={error} onRetry={handleRetry} />;
  }

  return (
    <div className="flex-1 px-4 py-6 sm:px-6 lg:px-8 flex flex-col h-full bg-white dark:bg-zinc-950 rounded-xl">
      <RepositoryHeader
        totalRepos={filteredRepos.length}
        onSearch={handleSearch}
        onRefresh={handleRetry}
        loading={loading}
      />
      <div className="mt-2 divide-y divide-gray-200 dark:divide-gray-800 scrollbar-hidden overflow-scroll overflow-y-auto overflow-x-hidden flex-1">
        {loading ? (
          <RepositoryLoader />
        ) : filteredRepos.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="text-gray-500 dark:text-gray-400 mb-4">
              {searchQuery ? (
                <>
                  <p className="text-lg font-medium mb-2">No repositories found</p>
                  <p className="text-sm">Try adjusting your search terms</p>
                </>
              ) : (
                <>
                  <p className="text-lg font-medium mb-2">No repositories available</p>
                  <p className="text-sm">Connect your GitHub account to get started</p>
                </>
              )}
            </div>
          </div>
        ) : (
          filteredRepos.map((repo) => (
            <RepositoryCard key={`${repo.owner}-${repo.name}`} repo={repo} />
          ))
        )}
      </div>
    </div>
  );
};

export default RepositoryList;
