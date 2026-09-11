import Link from "next/link";
import { redirect } from "next/navigation";
import { currentSession } from "@/lib/session";
import { ApiDocumentation } from "@/components/api-documentation";

export default async function ApiDocsPage() {
  if (!await currentSession()) redirect("/login");
  return <main className="max-w-5xl mx-auto p-6 md:p-10">
    <Link href="/dashboard" className="text-button">← Back to dashboard</Link>
    <h1 className="text-3xl font-semibold mt-6">cveator API documentation</h1>
    <p className="muted mt-3">Authentication, vulnerabilities, software, alerts, billing and account management.</p>
    <ApiDocumentation />
  </main>;
}
