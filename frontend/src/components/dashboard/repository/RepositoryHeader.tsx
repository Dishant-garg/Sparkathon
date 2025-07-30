import { Input } from "@/components/ui/input";
import { Search, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState, useEffect, useCallback } from "react";

interface RepositoryHeaderProps {
  totalRepos: number;
  onSearch: (query: string) => void;
  onRefresh?: () => void;
  loading?: boolean;
}

export const RepositoryHeader = ({
  totalRepos,
  onSearch,
  onRefresh,
  loading = false,
}: RepositoryHeaderProps) => {
  const [searchQuery, setSearchQuery] = useState("");

  // Debounce search to avoid too many API calls
  const debouncedSearch = useCallback(
    (() => {
      let timeoutId: NodeJS.Timeout;
      return (query: string) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
          onSearch(query);
        }, 300);
      };
    })(),
    [onSearch]
  );

  useEffect(() => {
    debouncedSearch(searchQuery);
  }, [searchQuery, debouncedSearch]);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  };

  const handleRefresh = () => {
    if (onRefresh) {
      onRefresh();
    }
  };

  return (
    <>
      <div className="flex flex-col items-start justify-between space-y-4 md:flex-row md:items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-black dark:text-white">
            Repositories
          </h1>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            {totalRepos} total repositories
          </p>
        </div>
        
        {onRefresh && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={loading}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        )}
      </div>
      
      <div className="mt-6 relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
        <Input
          type="search"
          placeholder="Search repositories by name, language, or description..."
          className="max-w-md pl-10"
          value={searchQuery}
          onChange={handleSearchChange}
          disabled={loading}
        />
      </div>
    </>
  );
};
