import { vulnpilotLogo, vulnpilotLogoLight } from "@/assets";
import { useTheme } from "./ThemeProvider";
import { cn } from "@/lib/utils";

interface VulnpilotLogoProps {
  className?: string;
}

const VulnpilotLogo = ({ className }: VulnpilotLogoProps) => {
  const { theme } = useTheme();
  return (
    <img
      src={theme === "dark" ? vulnpilotLogoLight : vulnpilotLogo}
      alt="Vulnpilot Logo"
      className={cn(className)}
    />
  );
};

export default VulnpilotLogo; 