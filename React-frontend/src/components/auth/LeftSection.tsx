import { MetricsCard } from "./MetricsCard";
import { StatsCard } from "./StatsCard";
import { authScreenLeftSectionBgImage } from "@/assets";

export const LeftSection = () => {
  return (
    <div
      className="hidden md:flex md:w-1/2 flex-col items-center justify-center bg-white dark:bg-zinc-900"
      style={{
        backgroundImage: `url(${authScreenLeftSectionBgImage})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      <div className="h-[322px] w-[90%] max-w-[474px] relative">
        <StatsCard />
        <MetricsCard />
      </div>
    </div>
  );
};
