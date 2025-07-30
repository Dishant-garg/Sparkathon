import { Input } from "@/components/ui/input";

interface RepositoryHeaderProps {
  totalRepos: number;
  onSearch: (query: string) => void;
}

export const RepositoryHeader = ({
  totalRepos,
  onSearch,
}: RepositoryHeaderProps) => {
  return (
    <>
      <div className="flex flex-col items-start justify-between space-y-4 md:flex-row">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Repositories</h1>
          <p className="mt-1 text-sm">{totalRepos} total repositories</p>
        </div>
      </div>
      <div className="mt-6">
        <Input
          type="search"
          placeholder="Search Repositories"
          className="max-w-md"
          onChange={(e) => onSearch(e.target.value)}
        />
      </div>
    </>
  );
};
