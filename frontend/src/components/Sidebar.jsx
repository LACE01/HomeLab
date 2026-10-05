import { useState, useRef, useEffect } from "react";
import { NavLink, useNavigate, Link, useLocation } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { CaretDown, SignOut, Devices, Binoculars, MagnifyingGlass } from "@phosphor-icons/react";
import { SECTIONS, sectionForPath } from "@/lib/navRegistry";

// Item 40: which sections the user has opened by hand. The section containing the
// current page is always open regardless, so you never lose your place.
const OPEN_KEY = "vulnops.sidebar.openSections";
const loadOpen = () => {
  try { return JSON.parse(localStorage.getItem(OPEN_KEY) || "{}"); } catch { return {}; }
};

const NavItem = ({ to, icon: Icon, label, testid }) => (
  <NavLink
    to={to}
    end={to === "/" || to === "/admin"}
    data-testid={testid}
    className={({ isActive }) =>
      `flex items-center gap-2 pl-8 pr-3 py-1 rounded-md text-[12.5px] transition-colors duration-150 ${
        isActive
          ? "bg-blue-500/10 text-blue-300"
          : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-100"
      }`
    }
  >
    <Icon size={14} weight="duotone" className="shrink-0" />
    <span className="truncate">{label}</span>
  </NavLink>
);

// One top-level entry. Clicking the label goes to the section's first page the
// user can access (and opens it); the caret just opens/closes. Two levels max.
const Section = ({ section, items, open, active, onToggle, onEnter }) => {
  const Icon = section.icon;
  return (
    <div className="mb-0.5">
      <div className={`flex items-center rounded-md ${active ? "text-slate-100" : "text-slate-400"} hover:bg-slate-800/40`}>
        <button type="button" data-testid={`nav-section-${section.key}`} onClick={onEnter}
          className="flex-1 min-w-0 flex items-center gap-2.5 px-3 py-1.5 text-[13px] text-left">
          <Icon size={16} weight="duotone" className={active ? "text-blue-400" : ""} />
          <span className="truncate">{section.label}</span>
        </button>
        {items.length > 1 && (
          <button type="button" onClick={onToggle} aria-label={`${open ? "Collapse" : "Expand"} ${section.label}`}
            className="px-2 py-1.5 text-slate-600 hover:text-slate-300">
            <CaretDown size={10} className={`transition-transform ${open ? "" : "-rotate-90"}`} />
          </button>
        )}
      </div>
      {open && items.length > 1 && (
        <div className="flex flex-col gap-0.5 mt-0.5 mb-1">
          {items.map((i) => <NavItem key={i.to} {...i} />)}
        </div>
      )}
    </div>
  );
};

// Every page renders its own <Layout> -> <Sidebar>, so React Router unmounts and
// remounts a brand-new Sidebar instance on every navigation (there's no single
// persistent shell wrapping all routes) -- a plain React ref/state scroll position
// can't survive that remount on its own, which is why clicking a nav item used to
// snap the list back to the top even when you were scrolled deep into e.g.
// Administration. SCROLL_KEY persists the last scroll offset in sessionStorage
// (survives remounts within the tab, cleared when the tab closes -- this is
// transient UI state, not a durable preference like the collapsed-groups setting
// below, which intentionally uses localStorage instead) and restores it the instant
// the new Sidebar mounts.
const SCROLL_KEY = "vulnops_sidebar_scroll";

export default function Sidebar() {
  const { user, logout, canAccess } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [openMap, setOpenMap] = useState(loadOpen());
  const navRef = useRef(null);
  const activeKey = sectionForPath(location.pathname);
  const setOpen = (key, val) => setOpenMap(prev => {
    const next = { ...prev, [key]: val };
    try { localStorage.setItem(OPEN_KEY, JSON.stringify(next)); } catch { /* private mode */ }
    return next;
  });

  useEffect(() => {
    const saved = sessionStorage.getItem(SCROLL_KEY);
    if (saved && navRef.current) navRef.current.scrollTop = parseInt(saved, 10) || 0;
  }, []);

  // Role-gated: only pages this role can open; sections with none are hidden.
  const visible = SECTIONS
    .map((sec) => ({ sec, items: sec.items.filter((i) => canAccess(i.to)) }))
    .filter((x) => x.items.length > 0);

  return (
    <aside data-testid="sidebar" className="w-60 shrink-0 bg-[#0D1117] border-r border-[#30363D] flex flex-col h-screen sticky top-0">
      <div className="px-4 py-4 border-b border-[#30363D] flex items-center gap-2">
        <Binoculars size={22} weight="duotone" className="text-blue-400" />
        <div>
          <div className="text-[15px] font-semibold tracking-tight text-slate-100">Nightwatch</div>
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Security Operations</div>
        </div>
      </div>

      <button
        onClick={() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }))}
        className="mx-2 mt-3 mb-1 flex items-center justify-between gap-2 px-3 py-1.5 rounded-md border border-[#30363D] text-slate-500 hover:text-slate-300 hover:border-slate-600 transition-colors">
        <span className="flex items-center gap-2 text-[12.5px]"><MagnifyingGlass size={14}/> Search…</span>
        <kbd className="text-[10px] font-mono border border-[#30363D] rounded px-1">⌘K</kbd>
      </button>
      <nav ref={navRef} data-testid="sidebar-nav" onScroll={(e) => sessionStorage.setItem(SCROLL_KEY, String(e.currentTarget.scrollTop))} className="flex-1 overflow-y-auto py-3 px-2">
        {visible.map(({ sec, items }) => {
          const isActive = sec.key === activeKey;
          const isOpen = isActive || !!openMap[sec.key];
          return (
            <Section key={sec.key} section={sec} items={items} active={isActive} open={isOpen}
              onToggle={() => setOpen(sec.key, !isOpen)}
              onEnter={() => { setOpen(sec.key, true); if (!isActive) nav(items[0].to); }} />
          );
        })}
      </nav>

      <div className="border-t border-[#30363D] p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-[12px] text-slate-200 truncate">{user?.name}</div>
            <div className="text-[10px] text-slate-500 font-mono uppercase">{user?.role}</div>
          </div>
          <Link to="/security" title="Security settings" className="text-slate-500 hover:text-slate-200 transition-colors">
            <Devices size={18} />
          </Link>
          <button
            data-testid="logout-btn"
            onClick={async () => { await logout(); nav("/login"); }}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            title="Sign out"
          >
            <SignOut size={18} />
          </button>
        </div>
      </div>
    </aside>
  );
}
