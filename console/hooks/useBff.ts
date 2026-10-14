"use client";
import useSWR, { type SWRResponse } from "swr";
import { swrFetcher } from "@/lib/client/bff";

/**
 * Stale-while-revalidate read through the BFF. `fallback` is the server-rendered value so the
 * first paint has data; live events revalidate mounted keys (see LiveProvider).
 */
export function useBff<T>(path: string | null, fallback?: T | null): SWRResponse<T> {
  return useSWR<T>(path, swrFetcher, {
    fallbackData: fallback ?? undefined,
    revalidateOnFocus: true,
    keepPreviousData: true,
    dedupingInterval: 800,
  });
}
