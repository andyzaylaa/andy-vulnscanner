import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, FolderOpen, Trash2, Edit, Camera, Shield, DoorOpen, Flame, Volume2, X } from 'lucide-react';
import { listProjects, createProject, deleteProject } from '../services/api';

export default function Dashboard() {
  const [projects, setProjects] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: '', description: '', client_name: '', location: '' });
  const navigate = useNavigate();

  useEffect(() => { loadProjects(); }, []);

  const loadProjects = async () => {
    try {
      const res = await listProjects();
      setProjects(res.data);
    } catch (err) {
      console.error('Failed to load projects:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const res = await createProject(form);
      setShowModal(false);
      setForm({ name: '', description: '', client_name: '', location: '' });
      navigate(`/project/${res.data.id}`);
    } catch (err) {
      console.error('Failed to create project:', err);
    }
  };

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (window.confirm('Delete this project? This cannot be undone.')) {
      await deleteProject(id);
      loadProjects();
    }
  };

  const systemIcons = {
    cctv: Camera,
    access_control: Shield,
    fire: Flame,
    sound: Volume2,
    gate: DoorOpen,
    video_door_phone: DoorOpen,
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Projects</h2>
          <p style={{ color: 'var(--text-light)', fontSize: '14px' }}>
            Manage your security system design projects
          </p>
        </div>
        <button className="btn btn-primary btn-lg" onClick={() => setShowModal(true)}>
          <Plus size={18} /> New Project
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-4" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#dbeafe' }}><FolderOpen size={20} color="#1e40af" /></div>
          <div className="stat-value">{projects.length}</div>
          <div className="stat-label">Total Projects</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#dcfce7' }}><Camera size={20} color="#166534" /></div>
          <div className="stat-value">{projects.reduce((s, p) => s + (p.drawing_count || 0), 0)}</div>
          <div className="stat-label">Drawings Uploaded</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#f3e8ff' }}><Shield size={20} color="#6b21a8" /></div>
          <div className="stat-value">{projects.reduce((s, p) => s + (p.product_count || 0), 0)}</div>
          <div className="stat-label">Products Selected</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#fce4e4' }}><Flame size={20} color="#991b1b" /></div>
          <div className="stat-value">6</div>
          <div className="stat-label">System Types</div>
        </div>
      </div>

      {/* Project List */}
      {loading ? (
        <div className="loading"><div className="spinner" /> Loading projects...</div>
      ) : projects.length === 0 ? (
        <div className="empty-state">
          <FolderOpen size={48} />
          <h3>No projects yet</h3>
          <p>Create your first security system design project</p>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            <Plus size={16} /> Create Project
          </button>
        </div>
      ) : (
        <div className="grid grid-3">
          {projects.map(project => (
            <div
              key={project.id}
              className="card project-card"
              onClick={() => navigate(`/project/${project.id}`)}
            >
              <div className="card-body">
                <div className="project-name">{project.name}</div>
                <div className="project-meta">
                  {project.client_name && <span>{project.client_name}</span>}
                  {project.location && <span> | {project.location}</span>}
                </div>
                {project.description && (
                  <p style={{ fontSize: 13, color: 'var(--text-light)', marginTop: 8 }}>
                    {project.description.slice(0, 100)}
                  </p>
                )}
                <div className="project-stats">
                  <span><Camera size={14} /> {project.drawing_count || 0} drawings</span>
                  <span><Shield size={14} /> {project.product_count || 0} products</span>
                  <span className={`badge badge-${project.status || 'draft'}`}>{project.status || 'draft'}</span>
                </div>
              </div>
              <div style={{ padding: '8px 16px', borderTop: '1px solid var(--border-light)', display: 'flex', justifyContent: 'flex-end' }}>
                <button className="btn btn-sm btn-outline" onClick={(e) => handleDelete(e, project.id)}>
                  <Trash2 size={12} /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>New Project</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}><X size={20} /></button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="modal-body">
                <div className="form-group">
                  <label>Project Name *</label>
                  <input
                    className="form-control"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    placeholder="e.g., Office Building Security"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Client Name</label>
                  <input
                    className="form-control"
                    value={form.client_name}
                    onChange={e => setForm({ ...form, client_name: e.target.value })}
                    placeholder="e.g., ABC Corporation"
                  />
                </div>
                <div className="form-group">
                  <label>Location</label>
                  <input
                    className="form-control"
                    value={form.location}
                    onChange={e => setForm({ ...form, location: e.target.value })}
                    placeholder="e.g., Dubai, UAE"
                  />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <textarea
                    className="form-control"
                    value={form.description}
                    onChange={e => setForm({ ...form, description: e.target.value })}
                    placeholder="Brief project description..."
                    rows={3}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-outline" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={!form.name.trim()}>Create Project</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
