import { notFound, redirect } from "next/navigation";
import { currentSession } from "@/lib/session";
import { VulnerabilityDetailView } from "@/components/vulnerability-detail";

export default async function CvePage({ params }: { params: Promise<{ cveId: string }> }) {
  if (!await currentSession()) redirect("/login");
  const { cveId } = await params;
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) notFound();
  return <VulnerabilityDetailView cveId={cveId.toUpperCase()} />;
}
