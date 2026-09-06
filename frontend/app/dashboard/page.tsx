import { redirect } from "next/navigation";

import { Dashboard, type DashboardView } from "@/components/dashboard";
import { currentBilling } from "@/lib/billing";
import { currentSession } from "@/lib/session";

export default async function DashboardPage({ searchParams }: { searchParams: Promise<{ view?: string }> }) {
  const user = await currentSession();
  if (!user) {
    redirect("/login");
  }
  const billing = await currentBilling();
  const { view } = await searchParams;
  const initialView: DashboardView = view === "software" || view === "intelligence" || view === "billing" ? view : "overview";
  return <Dashboard billing={billing} user={user} initialView={initialView} />;
}
