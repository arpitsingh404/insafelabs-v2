import { AssessmentModule } from "@/components/AssessmentModule";
import { Code2 } from "lucide-react";

const SAMPLE_CODE = `import os
import sqlite3

def login(username, password):
    conn = sqlite3.connect("app.db")
    # vulnerable: string concatenation
    query = "SELECT * FROM users WHERE user='" + username + "'"
    conn.execute(query)
    os.system("logger " + username)
    api_key = "sk_live_EXAMPLE_REDACTED_DO_NOT_USE"
    return query`;

export default function CodeReview() {
  return (
    <AssessmentModule
      module="code-review"
      label="Secure Code Review"
      sublabel="Upload a source file (Python, JS, Java, Go, PHP…) or paste code, then run an AI-driven review · line-level findings · OWASP & SANS Top 25 aligned"
      icon={Code2}
      standard="OWASP · SANS Top 25"
      languageField="language"
      runLabel="Run Secure Review"
      fields={[
        { key: "code", label: "Source Code (upload a file or paste)", type: "textarea", placeholder: "Upload a code file above, or paste the source to review…", mono: true, rows: 16, upload: true },
        { key: "language", label: "Language / Framework (auto-detected on upload)", type: "text", placeholder: "python / node.js / java / go …" },
      ]}
      sample={{ code: SAMPLE_CODE, language: "python" }}
    />
  );
}
