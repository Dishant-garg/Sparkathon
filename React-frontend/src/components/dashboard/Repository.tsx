import useGitHub from "@/hooks/useGithub";
import { useEffect, useMemo, useState } from "react";
import { RepositoryHeader } from "@/components/dashboard/repository/RepositoryHeader";
import { RepositoryCard } from "@/components/dashboard/repository/RepositoryCard";
import { RepositoryLoader } from "@/components/dashboard/repository/RepositoryLoader";
import { RepositoryError } from "@/components/dashboard/repository/RepositoryError";

const RepositoryList = () => {
  const { repos, fetchRepositories, loading, error } = useGitHub();
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    fetchRepositories();
  }, [fetchRepositories]);

  const filteredRepos = useMemo(() => {
    if (!searchQuery) return repos;

    const query = searchQuery.toLowerCase();
    return repos.filter((repo) => {
      return (
        repo.name.toLowerCase().includes(query) ||
        (repo.language && repo.language.toLowerCase().includes(query)) ||
        (repo.private ? "private" : "public").includes(query)
      );
    });
  }, [repos, searchQuery]);

  if (error) {
    return <RepositoryError error={error} onRetry={fetchRepositories} />;
  }

  return (
    <div className="flex-1 px-4 py-6 sm:px-6 lg:px-8 flex flex-col h-full bg-white dark:bg-zinc-950 rounded-xl">
      <RepositoryHeader
        totalRepos={filteredRepos.length}
        onSearch={setSearchQuery}
      />
      <div className="mt-2 divide-y divide-gray-200 dark:divide-gray-800 scrollbar-hidden overflow-scroll overflow-y-auto overflow-x-hidden flex-1">
        {loading ? (
          <RepositoryLoader />
        ) : (
          filteredRepos.map((repo) => (
            <RepositoryCard key={repo.name} repo={repo} />
          ))
        )}
      </div>
    </div>
  );
};

export default RepositoryList;
