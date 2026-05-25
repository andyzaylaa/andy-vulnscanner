import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Upload, FileImage, Cpu, Search, Package, FileSpreadsheet,
  Download, Trash2, Plus, Camera, Shield, DoorOpen, Flame,
  Volume2, X, AlertCircle, CheckCircle, ChevronRight, Eye
} from 'lucide-react';
import {
  getProject, uploadDrawing, listDrawings, analyzeDrawing,
  getDrawingImage, uploadBOQ, getBOQEntries, getProjectProducts,
  addProductToProject, removeProjectProduct, searchProducts,
  downloadExcelReport, calculateCables, calculateAccessories,
  getProjectSummary
} from '../services/api';

const SYSTEM_COLORS = {
  cctv: '#2196F3', access_control: '#4CAF50', gate: '#FF9800',
  video_door_phone: '#9C27B0', fire: '#F44336', sound: '#607D8B',
  intercom: '#795548', alarm: '#E91E63',
};

export default function ProjectView() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);
  const boqInputRef = useRef(null);

  const [project, setProject] = useState(null);
  const [drawings, setDrawings] = useState([]);
  const [boqEntries, setBOQEntries] = useState([]);
  const [projectProducts, setProjectProducts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [cables, setCables] = useState([]);
  const [accessories, setAccessories] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => { loadAll(); }, [projectId]);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const loadAll = async () => {
    setLoading(true);
    try {
      const [projRes, drawRes, boqRes, prodRes] = await Promise.all([
        getProject(projectId),
        listDrawings(projectId),
        getBOQEntries(projectId),
        getProjectProducts(projectId),
      ]);
      setProject(projRes.data);
      setDrawings(drawRes.data);
      setBOQEntries(boqRes.data);
      setProjectProducts(prodRes.data);

      try {
        const sumRes = await getProjectSummary(projectId);
        setSummary(sumRes.data);
      } catch {}
      try {
        const [cabRes, accRes] = await Promise.all([
          calculateCables(projectId), calculateAccessories(projectId)
        ]);
        setCables(cabRes.data.cables || []);
        setAccessories(accRes.data.accessories || []);
      } catch {}
    } catch (err) {
      console.error('Failed to load project:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleUploadDrawing = async (e) => {
    const files = e.target.files;
    if (!files?.length) return;
    setUploading(true);
    try {
      for (const file of files) {
        await uploadDrawing(projectId, file);
      }
      showToast('Drawing(s) uploaded successfully', 'success');
      const res = await listDrawings(projectId);
      setDrawings(res.data);
    } catch (err) {
      showToast('Failed to upload drawing', 'error');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleAnalyze = async (drawingId) => {
    setAnalyzing(drawingId);
    try {
      await analyzeDrawing(drawingId);
      showToast('AI analysis complete! View the drawing to see results.', 'success');
      const res = await listDrawings(projectId);
      setDrawings(res.data);
      await loadAll();
    } catch (err) {
      showToast('Analysis failed. Check API key configuration.', 'error');
    } finally {
      setAnalyzing(null);
    }
  };

  const handleUploadBOQ = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      await uploadBOQ(projectId, file);
      showToast('BOQ imported successfully', 'success');
      const res = await getBOQEntries(projectId);
      setBOQEntries(res.data);
    } catch (err) {
      showToast('Failed to import BOQ', 'error');
    }
    e.target.value = '';
  };

  const handleDownloadReport = async () => {
    try {
      const res = await downloadExcelReport(projectId);
      const blob = new Blob([res.data], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project?.name || 'Project'}_Report.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Report downloaded!', 'success');
    } catch (err) {
      showToast('Failed to generate report', 'error');
    }
  };

  const handleRemoveProduct = async (ppId) => {
    await removeProjectProduct(ppId);
    const res = await getProjectProducts(projectId);
    setProjectProducts(res.data);
  };

  if (loading) return <div className="loading"><div className="spinner" /> Loading project...</div>;
  if (!project) return <div className="empty-state"><AlertCircle size={48} /><h3>Project not found</h3></div>;

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'drawings', label: `Drawings (${drawings.length})` },
    { id: 'products', label: `Products (${projectProducts.length})` },
    { id: 'boq', label: `BOQ (${boqEntries.length})` },
    { id: 'cables', label: 'Cables & Accessories' },
    { id: 'report', label: 'Report' },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="breadcrumb"><Link to="/">Projects</Link> <ChevronRight size={12} style={{ display: 'inline' }} /> {project.name}</div>
          <h2>{project.name}</h2>
        </div>
        <div className="btn-group">
          <button className="btn btn-outline" onClick={() => navigate(`/project/${projectId}/products`)}>
            <Search size={16} /> Search Products
          </button>
          <button className="btn btn-success" onClick={handleDownloadReport}>
            <Download size={16} /> Export Excel
          </button>
        </div>
      </div>

      <div className="tabs">
        {tabs.map(tab => (
          <button key={tab.id} className={`tab ${activeTab === tab.id ? 'active' : ''}`} onClick={() => setActiveTab(tab.id)}>
            {tab.label}
          </button>
        ))}
      </div>

      {/* OVERVIEW TAB */}
      {activeTab === 'overview' && (
        <div>
          <div className="grid grid-4" style={{ marginBottom: 24 }}>
            <div className="stat-card">
              <div className="stat-value">{drawings.length}</div>
              <div className="stat-label">Drawings</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{projectProducts.length}</div>
              <div className="stat-label">Products</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{summary?.total_devices || 0}</div>
              <div className="stat-label">Total Devices</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">${(summary?.total_cost || 0).toLocaleString()}</div>
              <div className="stat-label">Estimated Cost</div>
            </div>
          </div>

          <div className="grid grid-2">
            <div className="card">
              <div className="card-header"><h3>Project Details</h3></div>
              <div className="card-body">
                <p><strong>Client:</strong> {project.client_name || 'N/A'}</p>
                <p><strong>Location:</strong> {project.location || 'N/A'}</p>
                <p><strong>Status:</strong> <span className="badge">{project.status}</span></p>
                <p><strong>Description:</strong> {project.description || 'No description'}</p>
              </div>
            </div>
            <div className="card">
              <div className="card-header"><h3>System Breakdown</h3></div>
              <div className="card-body">
                {summary?.by_system && Object.entries(summary.by_system).map(([sys, data]) => (
                  <div key={sys} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border-light)' }}>
                    <span className={`badge badge-${sys}`}>{sys.replace('_', ' ')}</span>
                    <span style={{ fontSize: 14 }}>{data.devices} devices | ${data.cost.toLocaleString()}</span>
                  </div>
                ))}
                {(!summary?.by_system || Object.keys(summary.by_system).length === 0) && (
                  <p style={{ color: 'var(--text-light)', fontSize: 14 }}>No products added yet. Upload a drawing and run AI analysis.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DRAWINGS TAB */}
      {activeTab === 'drawings' && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <input type="file" ref={fileInputRef} accept=".pdf,.png,.jpg,.jpeg,.bmp,.tiff" multiple onChange={handleUploadDrawing} style={{ display: 'none' }} />
            <button className="btn btn-primary" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
              {uploading ? <><div className="spinner" style={{ width: 16, height: 16, margin: 0 }} /> Uploading...</> : <><Upload size={16} /> Upload Drawing</>}
            </button>
          </div>

          {drawings.length === 0 ? (
            <div className="upload-zone" onClick={() => fileInputRef.current?.click()}>
              <FileImage size={48} />
              <p>Drop your floor plans / drawings here</p>
              <p className="upload-hint">Supports PDF, PNG, JPG, BMP, TIFF (max 50MB)</p>
            </div>
          ) : (
            <div className="grid grid-3">
              {drawings.map(d => (
                <div key={d.id} className="card">
                  <div style={{ height: 180, overflow: 'hidden', background: '#f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <img src={getDrawingImage(d.id)} alt={d.filename} style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} />
                  </div>
                  <div className="card-body" style={{ padding: 12 }}>
                    <p style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{d.filename}</p>
                    <p style={{ fontSize: 12, color: 'var(--text-light)' }}>{d.width}x{d.height} px | {d.file_type}</p>
                    <div className="btn-group" style={{ marginTop: 8 }}>
                      <button className="btn btn-sm btn-primary" onClick={() => navigate(`/project/${projectId}/drawing/${d.id}`)}>
                        <Eye size={12} /> View
                      </button>
                      <button
                        className="btn btn-sm btn-accent"
                        onClick={() => handleAnalyze(d.id)}
                        disabled={analyzing === d.id}
                      >
                        {analyzing === d.id ? <><div className="spinner" style={{ width: 12, height: 12, margin: 0 }} /> Analyzing...</> : <><Cpu size={12} /> AI Analyze</>}
                      </button>
                      {d.analysis_result && Object.keys(d.analysis_result).length > 0 && (
                        <span className="tag"><CheckCircle size={10} /> Analyzed</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* PRODUCTS TAB */}
      {activeTab === 'products' && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <button className="btn btn-primary" onClick={() => navigate(`/project/${projectId}/products`)}>
              <Plus size={16} /> Add Products
            </button>
          </div>
          {projectProducts.length === 0 ? (
            <div className="empty-state">
              <Package size={48} />
              <h3>No products added</h3>
              <p>Search and add products, or upload a drawing for AI recommendations</p>
            </div>
          ) : (
            <div className="card">
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>#</th><th>Model</th><th>Name</th><th>System</th><th>Qty</th><th>Location</th><th>Cable</th><th>Price</th><th>Total</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {projectProducts.map((pp, i) => (
                      <tr key={pp.id}>
                        <td>{i + 1}</td>
                        <td><strong>{pp.product?.model_number}</strong></td>
                        <td>{pp.product?.name}</td>
                        <td><span className={`badge badge-${pp.system_type}`}>{pp.system_type.replace('_', ' ')}</span></td>
                        <td>{pp.quantity}</td>
                        <td>{pp.location_note}</td>
                        <td>{pp.cable_type ? `${pp.cable_type} (${pp.cable_length_m}m)` : '-'}</td>
                        <td>${pp.product?.price?.toFixed(2)}</td>
                        <td><strong>${((pp.product?.price || 0) * pp.quantity).toFixed(2)}</strong></td>
                        <td>
                          <button className="btn btn-sm btn-outline" onClick={() => handleRemoveProduct(pp.id)}>
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* BOQ TAB */}
      {activeTab === 'boq' && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <input type="file" ref={boqInputRef} accept=".xlsx,.xls,.csv" onChange={handleUploadBOQ} style={{ display: 'none' }} />
            <button className="btn btn-primary" onClick={() => boqInputRef.current?.click()}>
              <Upload size={16} /> Import BOQ
            </button>
            <span style={{ marginLeft: 12, fontSize: 13, color: 'var(--text-light)' }}>Supports Excel (.xlsx) and CSV files</span>
          </div>

          {boqEntries.length === 0 ? (
            <div className="upload-zone" onClick={() => boqInputRef.current?.click()}>
              <FileSpreadsheet size={48} />
              <p>Upload your Bill of Quantities (BOQ)</p>
              <p className="upload-hint">The system will auto-match items to products in the catalog</p>
            </div>
          ) : (
            <div className="card">
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr><th>#</th><th>Description</th><th>Model</th><th>Qty</th><th>Unit</th><th>Unit Price</th><th>Total</th><th>System</th><th>Matched</th></tr>
                  </thead>
                  <tbody>
                    {boqEntries.map(e => (
                      <tr key={e.id}>
                        <td>{e.item_number}</td>
                        <td>{e.description}</td>
                        <td><strong>{e.model_number}</strong></td>
                        <td>{e.quantity}</td>
                        <td>{e.unit}</td>
                        <td>${e.unit_price.toFixed(2)}</td>
                        <td>${e.total_price.toFixed(2)}</td>
                        <td><span className={`badge badge-${e.system_type}`}>{e.system_type.replace('_', ' ')}</span></td>
                        <td>{e.matched_product_id ? <CheckCircle size={14} color="green" /> : <AlertCircle size={14} color="orange" />}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* CABLES & ACCESSORIES TAB */}
      {activeTab === 'cables' && (
        <div className="grid grid-2">
          <div className="card">
            <div className="card-header"><h3>Cable Schedule</h3></div>
            <div className="card-body">
              {cables.length === 0 ? (
                <p style={{ color: 'var(--text-light)', fontSize: 14 }}>Run AI analysis on drawings to calculate cables</p>
              ) : (
                <div className="table-wrapper">
                  <table>
                    <thead><tr><th>Cable Type</th><th>Total (m)</th><th>Rolls</th><th>System</th></tr></thead>
                    <tbody>
                      {cables.map((c, i) => (
                        <tr key={i}>
                          <td><strong>{c.cable_type}</strong></td>
                          <td>{c.total_length_m}m</td>
                          <td>{c.quantity_rolls} x {c.roll_length_m}m</td>
                          <td><span className={`badge badge-${c.system_type}`}>{c.system_type.replace('_', ' ')}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
          <div className="card">
            <div className="card-header"><h3>Accessories</h3></div>
            <div className="card-body">
              {accessories.length === 0 ? (
                <p style={{ color: 'var(--text-light)', fontSize: 14 }}>Run AI analysis on drawings to calculate accessories</p>
              ) : (
                <div className="table-wrapper">
                  <table>
                    <thead><tr><th>Accessory</th><th>Model</th><th>Qty</th><th>For</th></tr></thead>
                    <tbody>
                      {accessories.map((a, i) => (
                        <tr key={i}>
                          <td>{a.name}</td>
                          <td><strong>{a.model_number}</strong></td>
                          <td>{a.quantity}</td>
                          <td style={{ fontSize: 12 }}>{a.for_product}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* REPORT TAB */}
      {activeTab === 'report' && (
        <div>
          <div className="card">
            <div className="card-header">
              <h3>Project Report</h3>
              <button className="btn btn-success" onClick={handleDownloadReport}>
                <Download size={16} /> Download Excel Report
              </button>
            </div>
            <div className="card-body">
              <p style={{ marginBottom: 16 }}>The Excel report includes the following sheets:</p>
              <div className="grid grid-3">
                {[
                  { name: 'Project Summary', desc: 'Cover page with project info and system summary' },
                  { name: 'Product List', desc: 'Complete list of all products with quantities and pricing' },
                  { name: 'By System Type', desc: 'Products grouped by CCTV, access control, fire, etc.' },
                  { name: 'Cable Schedule', desc: 'All cables needed with lengths and roll quantities' },
                  { name: 'Accessories', desc: 'Brackets, connectors, junction boxes, etc.' },
                  { name: 'Pricing Summary', desc: 'Total costs breakdown by category' },
                ].map(sheet => (
                  <div key={sheet.name} style={{ padding: 12, border: '1px solid var(--border-light)', borderRadius: 8 }}>
                    <strong style={{ fontSize: 14 }}>{sheet.name}</strong>
                    <p style={{ fontSize: 12, color: 'var(--text-light)', marginTop: 4 }}>{sheet.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {toast && <div className={`toast ${toast.type}`}>{toast.msg}</div>}
    </div>
  );
}
