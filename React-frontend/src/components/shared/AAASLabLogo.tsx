import { aaasLabLogo, aaasLabLogoLight } from "@/assets";
import { useTheme } from "./ThemeProvider";
import { cn } from "@/lib/utils";

interface AAASLabLogoProps {
  className?: string;
}

const AAASLabLogo = ({ className }: AAASLabLogoProps) => {
  const { theme } = useTheme();
  return (
    <img
      src={theme === "dark" ? aaasLabLogoLight : aaasLabLogo}
      alt="Aaas Labs Logo"
      className={cn(className)}
    />
  );
};

export default AAASLabLogo;
