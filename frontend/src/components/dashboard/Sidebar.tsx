import { useEffect, useState } from "react";
import { useTheme } from "@/components/shared/ThemeProvider";
import {
  LogOut,
  Sun,
  Moon,
  Settings,
  MoreVertical,
  Menu,
  Workflow,
  FileText,
  BookCopy,
} from "lucide-react";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { useNavigate } from "react-router-dom";
import VulnpilotLogo from "../shared/VulnpilotLogo";
import useAuth from "@/hooks/useAuth";

export function Sidebar() {
  const navigate = useNavigate();
  const [activeItem, setActiveItem] = useState("repository");
  const { theme, setTheme } = useTheme();
  const { user } = useAuth();

  useEffect(() => {
    if (window.location.pathname === "/dashboard") {
      navigate("/dashboard/repository", { replace: true });
    }
  }, [navigate]);

  const handleItemClick = (item: string) => {
    navigate(`/dashboard/${item}`);
    setActiveItem(item);
  };

  const { logout } = useAuth();

  const SidebarContent = () => (
    <div
      className={`flex flex-col h-full dark:bg-zinc-950 bg-white transition-colors duration-200`}
    >
      <div className="p-6">
        <div className="flex items-center space-x-2">
          <VulnpilotLogo className="h-10 w-10" />
          <h2 className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600 font-bold text-xl">
            Vulnpilot
          </h2>
        </div>
      </div>

      <div className="flex-1 px-4">
        <nav className="space-y-1">
          {[
            { icon: BookCopy, label: "Repository" },
            { icon: Workflow, label: "Workflow" },
            { icon: FileText, label: "Report" },
          ].map(({ icon: Icon, label }) => (
            <Button
              key={label}
              variant="ghost"
              className={`w-full justify-start ${
                activeItem === label.toLowerCase()
                  ? `hover:bg-blue-400`
                  : `hover:bg-blue-50 dark:hover:bg-zinc-950`
              }  transition-colors duration-200 text-black dark:text-white
                ${
                  activeItem === label.toLowerCase()
                    ? "bg-blue-500 text-white"
                    : ""
                }`}
              onClick={() => handleItemClick(label.toLowerCase())}
            >
              <Icon className="mr-3 h-4 w-4" />
              <span className="font-medium">{label}</span>
            </Button>
          ))}
        </nav>
      </div>

      <div className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Avatar className="h-10 w-10">
              <AvatarImage src={`${user?.avatar}`} alt="User" />
              <AvatarFallback className="bg-blue-100 text-blue-600">
                {user?.username.charAt(0)}
              </AvatarFallback>
            </Avatar>
            <div className="flex-1">
              <p className="text-sm font-semibold text-black dark:text-white">
                {user?.username}
              </p>
              <p className="text-xs text-gray-400">{user?.email}</p>
            </div>
          </div>
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreVertical className="h-4 w-4 dark:text-white" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-56" align="end">
              <div className="space-y-1">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      className="w-full justify-start hover:bg-blue-50 dark:hover:bg-blue-950"
                    >
                      {theme === "dark" ? (
                        <Moon className="mr-2 h-4 w-4" />
                      ) : (
                        <Sun className="mr-2 h-4 w-4" />
                      )}
                      Theme
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    <DropdownMenuItem
                      onClick={() => setTheme("light")}
                      className="cursor-pointer"
                    >
                      <Sun className="mr-2 h-4 w-4" /> Light
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => setTheme("dark")}
                      className="cursor-pointer"
                    >
                      <Moon className="mr-2 h-4 w-4" /> Dark
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => setTheme("system")}
                      className="cursor-pointer"
                    >
                      <Settings className="mr-2 h-4 w-4" /> System
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                <Button
                  variant="ghost"
                  className="w-full justify-start hover:bg-blue-50 dark:hover:bg-blue-950 text-red-500"
                  onClick={logout}
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  Logout
                </Button>
              </div>
            </PopoverContent>
          </Popover>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <div className="hidden md:flex md:w-72 md:flex-col">
        <SidebarContent />
      </div>

      <Sheet>
        <SheetTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="md:hidden fixed top-4 right-4 z-40 text-black dark:text-white"
          >
            <Menu className="h-4 w-4" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="w-72 p-0">
          <SidebarContent />
        </SheetContent>
      </Sheet>
    </>
  );
}
export default Sidebar;
