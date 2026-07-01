import { Question } from "@phosphor-icons/react";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";

/** Small inline "?" hint that shows an explainer on hover/focus/tap. Keyboard accessible
 *  (it's a real button), and works on touch devices via Radix's built-in tap handling. */
export default function InfoTip({ children, side = "top" }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" aria-label="What does this mean?"
          className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full text-slate-500 hover:text-slate-200 hover:bg-slate-700/50 align-text-top">
          <Question size={11} weight="bold" />
        </button>
      </TooltipTrigger>
      <TooltipContent side={side} className="max-w-[260px] text-[11px] leading-relaxed bg-[#161B22] border border-[#30363D] text-slate-200">
        {children}
      </TooltipContent>
    </Tooltip>
  );
}
