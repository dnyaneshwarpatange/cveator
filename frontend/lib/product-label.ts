import type { Product } from "@/lib/types";

export function productVersionLabel(product: Product): string {
  return !product.version || product.version === "*" ? "All versions" : product.version === "-" ? "Version unspecified" : product.version;
}
