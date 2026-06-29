import { format, formatDistanceToNow, parseISO, isBefore } from "date-fns";

export const fmtDate = (iso) => { try { return iso ? format(parseISO(iso), "yyyy-MM-dd HH:mm") : "—"; } catch { return iso || "—"; } };
export const fmtRel = (iso) => { try { return iso ? formatDistanceToNow(parseISO(iso), { addSuffix: true }) : "—"; } catch { return iso || "—"; } };
export const isOverdue = (iso) => { try { return iso && isBefore(parseISO(iso), new Date()); } catch { return false; } };
export const sevClass = (s) => ({Critical:"sev-critical",High:"sev-high",Medium:"sev-medium",Low:"sev-low",Info:"sev-info"})[s] || "sev-info";
