import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import VulnpilotLogo from "../shared/VulnpilotLogo";

export const StatsCard = () => {
  return (
    <Card className="absolute gap-3 top-0 left-0 h-[170px] w-full">
      <CardHeader>
        <div className="flex items-start gap-2">
          <VulnpilotLogo className="h-10" />
          <h2 className="text-black dark:text-white text-lg font-bold">
            AI-Powered Code Security & Auto-Fix
          </h2>
        </div>
      </CardHeader>
      <Separator />
      <CardContent className="flex justify-between">
        <StatItem value="50+" label="Attack Vectors" />
        <StatItem value="10K+" label="Developers" />
        <StatItem value="1M+" label="Scans Run" />
      </CardContent>
    </Card>
  );
};

const StatItem = ({ value, label }: { value: string; label: string }) => (
  <div className="text-center">
    <h3 className="text-black dark:text-white text-lg font-bold">{value}</h3>
    <p className="text-sm">{label}</p>
  </div>
);
