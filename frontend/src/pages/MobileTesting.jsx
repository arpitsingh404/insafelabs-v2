import { AssessmentModule } from "@/components/AssessmentModule";
import { ApkAnalyzer } from "@/components/ApkAnalyzer";
import { Smartphone } from "lucide-react";

export default function MobileTesting() {
  return (
    <div className="space-y-8">
      <ApkAnalyzer />
      <AssessmentModule
        module="mobile"
        label="Mobile Application Security Testing"
        sublabel="Static + dynamic analysis reasoning for iOS & Android · MASVS / NIST / OWASP-aligned"
        icon={Smartphone}
        standard="MASVS · NIST · OWASP Mobile"
        fields={[
          { key: "package_id", label: "App / Package ID", type: "text", placeholder: "com.acme.wallet" },
          { key: "platform", label: "Platform", type: "select", options: ["Android", "iOS", "Cross-platform (Flutter/React Native)"], default: "Android" },
          { key: "description", label: "App Description / Manifest / Notes", type: "textarea", placeholder: "Fintech wallet. Stores tokens in SharedPreferences, uses biometric login, custom TLS pinning, exported activities…", rows: 6 },
        ]}
        sample={{
          package_id: "com.acme.wallet",
          platform: "Android",
          description: "Consumer crypto wallet. Stores JWT + seed phrase in SharedPreferences, uses http for image CDN, exported deep-link activity, no root detection, biometric unlock optional.",
        }}
      />
    </div>
  );
}
