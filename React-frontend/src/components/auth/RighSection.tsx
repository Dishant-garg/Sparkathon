import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Github, Shield, Zap, Code } from "lucide-react";
import AAASLabLogo from "../shared/AAASLabLogo";
import useAuth from "@/hooks/useAuth";

const RightSection = () => {
  const { loginWithGithub } = useAuth();

  return (
    <div className="w-full md:w-1/2 bg-white dark:bg-zinc-900 flex flex-col items-center justify-center min-h-screen px-6 py-12">
      <div className="w-full max-w-md">
        <Card className="shadow-xl border-0 bg-white dark:bg-zinc-950 backdrop-blur">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-center gap-3 mb-6">
              <AAASLabLogo className="h-10 w-10" />
              <h2 className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600 font-bold text-xl">
                VulnPilot
              </h2>
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
              Join thousands of developers who trust VulnPilot to streamline
              their workflow
            </p>
          </CardHeader>

          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 gap-3 mb-2">
              <div className="flex items-start gap-3">
                <Shield className="h-5 w-5 text-blue-500 mt-1" />
                <div>
                  <h4 className="font-medium text-sm">
                    Advanced Security Scanning
                  </h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Detect vulnerabilities before they reach production
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Zap className="h-5 w-5 text-purple-500 mt-1" />
                <div>
                  <h4 className="font-medium text-sm">
                    Performance Optimization
                  </h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Identify bottlenecks and optimize your codebase
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Code className="h-5 w-5 text-green-500 mt-1" />
                <div>
                  <h4 className="font-medium text-sm">
                    Intelligent Code Fixes
                  </h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Get AI-powered suggestions to improve your code
                  </p>
                </div>
              </div>
            </div>

            <Button
              variant="outline"
              className="w-full mt-5 py-6 bg-gray-50 dark:bg-zinc-700 hover:bg-gray-100 dark:hover:bg-zinc-600 border border-gray-200 dark:border-zinc-600 flex items-center justify-center gap-3 transition-all"
              onClick={loginWithGithub}
            >
              <Github className="h-5 w-5" />
              <span className="font-medium">Continue with GitHub</span>
            </Button>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <div className="text-sm text-gray-500 dark:text-gray-400 mb-3">
            By signing up, you agree to our{" "}
            <a
              href="#"
              className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600 hover:underline font-medium"
            >
              Terms of Service
            </a>{" "}
            and{" "}
            <a
              href="#"
              className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600 hover:underline font-medium"
            >
              Privacy Policy
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RightSection;
