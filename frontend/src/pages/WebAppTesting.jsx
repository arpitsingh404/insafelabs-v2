import { AssessmentModule } from "@/components/AssessmentModule";
import { Globe } from "lucide-react";

export default function WebAppTesting() {
  return (
    <AssessmentModule
      module="web"
      label="Web Application Security Testing"
      sublabel="AI-driven pentest with live security-header recon · human-led validation"
      icon={Globe}
      standard="OWASP Top 10 · SANS 25"
      fields={[
        { key: "target", label: "Target URL", type: "text", placeholder: "https://app.target.com" },
        { key: "tech_stack", label: "Tech Stack", type: "text", placeholder: "React SPA + Node/Express + MongoDB, JWT auth" },
        { key: "scope_notes", label: "Scope & Notes", type: "textarea", placeholder: "In-scope features: login, file upload, search, admin panel…", rows: 5 },
      ]}
      sample={{
        target: "https://demo.testfire.net",
        tech_stack: "Java / JSP legacy stack, session cookies",
        scope_notes: "Online banking demo — login, funds transfer, search, account view.",
      }}
    />
  );
}
