import Sidebar from "./Sidebar";
import CommandPalette from "./CommandPalette";

export default function Layout({ children, title, subtitle, actions }) {
  return (
    <div className="flex min-h-screen bg-[#090C10] text-slate-100">
      {/* Global Cmd-K jump-to-page. Rendered once here so it's available on every
          screen without each page wiring it up. */}
      <CommandPalette />
      <Sidebar />
      <main className="flex-1 min-w-0">
        <header className="border-b border-[#30363D] bg-[#0D1117]/60 backdrop-blur sticky top-0 z-10">
          <div className="flex items-center justify-between px-6 py-3">
            <div className="min-w-0">
              <h1 className="text-[18px] font-semibold tracking-tight text-slate-100" data-testid="page-title">{title}</h1>
              {subtitle && <div className="text-[12px] text-slate-500 mt-0.5">{subtitle}</div>}
            </div>
            <div className="flex items-center gap-2">{actions}</div>
          </div>
        </header>
        <div className="px-6 py-5">{children}</div>
      </main>
    </div>
  );
}
