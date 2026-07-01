import {
  Wrench, Code, Key, Cloud, LockKey, ArrowsLeftRight, BookOpen,
} from "@phosphor-icons/react";

// Visual identity for each playbook category -- reused by the Playbooks board and the
// playbook detail flow so a category reads the same way everywhere. Kept inside the
// app's existing functional palette (red/orange/amber/blue/slate) plus the two
// restrained additions (violet, pink) already used for non-severity groupings on the
// Attack Path graph, so this doesn't introduce a new ad-hoc color language.
export const PLAYBOOK_CATEGORY_META = {
  patching: { label: "Patching", icon: Wrench, color: "#f97316" },
  appsec: { label: "AppSec", icon: Code, color: "#ef4444" },
  identity: { label: "Identity & Access", icon: Key, color: "#f59e0b" },
  cloud: { label: "Cloud & Config", icon: Cloud, color: "#3b82f6" },
  crypto: { label: "Cryptography", icon: LockKey, color: "#a78bfa" },
  network: { label: "Network", icon: ArrowsLeftRight, color: "#ec4899" },
  other: { label: "Other", icon: BookOpen, color: "#64748b" },
};

export function categoryMeta(category) {
  return PLAYBOOK_CATEGORY_META[category] || PLAYBOOK_CATEGORY_META.other;
}
