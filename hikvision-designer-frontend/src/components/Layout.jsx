import { Link, useLocation } from 'react-router-dom';
import { Home, FolderOpen, Search, FileText, Settings } from 'lucide-react';

export default function Layout({ children }) {
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Dashboard', icon: Home },
  ];

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>HikDesigner AI</h1>
          <div className="subtitle">Security Systems Design Tool</div>
        </div>
        <nav className="sidebar-nav">
          {navItems.map(item => (
            <Link
              key={item.path}
              to={item.path}
              className={location.pathname === item.path ? 'active' : ''}
            >
              <item.icon />
              {item.label}
            </Link>
          ))}
        </nav>
        <div style={{ padding: '16px 20px', borderTop: '1px solid rgba(255,255,255,0.1)', fontSize: '11px', opacity: 0.6 }}>
          v1.0.0 - AI Powered
        </div>
      </aside>
      <main className="main-content">
        {children}
      </main>
    </div>
  );
}
