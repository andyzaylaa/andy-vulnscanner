import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ChevronRight, Cpu, ZoomIn, ZoomOut, RotateCw,
  Eye, EyeOff, Layers, Plus, Trash2, CheckCircle
} from 'lucide-react';
import {
  getDrawingImage, analyzeDrawing, getDrawingPlacements,
  addPlacement, deletePlacement, listDrawings
} from '../services/api';

const SYSTEM_COLORS = {
  cctv: '#2196F3', access_control: '#4CAF50', gate: '#FF9800',
  video_door_phone: '#9C27B0', fire: '#F44336', sound: '#607D8B',
};

const SYMBOL_ICONS = {
  'CAM-DOME': '\u2299', 'CAM-BULLET': '\u25B8', 'CAM-PTZ': '\u25CE',
  'CAM-FISHEYE': '\u25C9', 'NVR': '\u25A3', 'AC-READER': '\u2AF0',
  'AC-TERMINAL': '\u229E', 'AC-CTRL': '\u25A6', 'GATE-BARRIER': '\u2AFF',
  'FIRE-SMOKE': '\u25EF', 'FIRE-HEAT': '\u25C7', 'FIRE-MCP': '\u2610',
  'FIRE-PANEL': '\u25A3', 'FIRE-SOUNDER': '\u25C8', 'SND-CEIL': '\u25CE',
  'SND-HORN': '\u25C1', 'VDP-DOOR': '\u2AF0', 'VDP-INDOOR': '\u25B1',
};

export default function DrawingView() {
  const { projectId, drawingId } = useParams();
  const canvasRef = useRef(null);

  const [drawing, setDrawing] = useState(null);
  const [placements, setPlacements] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [showSymbols, setShowSymbols] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedPlacement, setSelectedPlacement] = useState(null);
  const [visibleSystems, setVisibleSystems] = useState(new Set(Object.keys(SYSTEM_COLORS)));
  const [addingMode, setAddingMode] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => { loadDrawing(); }, [drawingId]);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const loadDrawing = async () => {
    try {
      const [drawRes, placRes] = await Promise.all([
        listDrawings(projectId),
        getDrawingPlacements(drawingId),
      ]);
      const d = drawRes.data.find(dr => dr.id === drawingId);
      setDrawing(d);
      setPlacements(placRes.data);
      if (d?.analysis_result) setAnalysis(d.analysis_result);
    } catch (err) {
      console.error('Failed to load drawing:', err);
    }
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    try {
      const res = await analyzeDrawing(drawingId);
      setAnalysis(res.data.analysis_result);
      showToast('AI analysis complete!', 'success');
      const placRes = await getDrawingPlacements(drawingId);
      setPlacements(placRes.data);
    } catch (err) {
      showToast('Analysis failed', 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleCanvasClick = async (e) => {
    if (!addingMode) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;

    try {
      await addPlacement({
        drawing_id: drawingId,
        system_type: addingMode.system_type,
        symbol_code: addingMode.code,
        x, y,
        label: addingMode.name,
        notes: '',
      });
      const res = await getDrawingPlacements(drawingId);
      setPlacements(res.data);
      showToast(`Placed ${addingMode.name}`, 'success');
    } catch (err) {
      showToast('Failed to add placement', 'error');
    }
    setAddingMode(null);
  };

  const handleDeletePlacement = async (id) => {
    await deletePlacement(id);
    setPlacements(prev => prev.filter(p => p.id !== id));
    setSelectedPlacement(null);
  };

  const toggleSystem = (sys) => {
    setVisibleSystems(prev => {
      const next = new Set(prev);
      if (next.has(sys)) next.delete(sys); else next.add(sys);
      return next;
    });
  };

  if (!drawing) return <div className="loading"><div className="spinner" /> Loading drawing...</div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="breadcrumb">
            <Link to="/">Projects</Link> <ChevronRight size={12} style={{ display: 'inline' }} />{' '}
            <Link to={`/project/${projectId}`}>Project</Link> <ChevronRight size={12} style={{ display: 'inline' }} /> Drawing
          </div>
          <h2>{drawing.filename}</h2>
        </div>
        <div className="btn-group">
          <button className="btn btn-accent" onClick={handleAnalyze} disabled={analyzing}>
            {analyzing ? <><div className="spinner" style={{ width: 16, height: 16, margin: 0 }} /> Analyzing...</> : <><Cpu size={16} /> AI Analyze</>}
          </button>
        </div>
      </div>

      <div className="split-layout">
        {/* Main Drawing Area */}
        <div className="panel-main">
          {/* Toolbar */}
          <div className="toolbar">
            <div className="toolbar-group">
              <button className="btn btn-sm btn-outline" onClick={() => setZoom(z => Math.min(z + 0.25, 3))}>
                <ZoomIn size={14} />
              </button>
              <span style={{ fontSize: 12, minWidth: 40, textAlign: 'center' }}>{Math.round(zoom * 100)}%</span>
              <button className="btn btn-sm btn-outline" onClick={() => setZoom(z => Math.max(z - 0.25, 0.25))}>
                <ZoomOut size={14} />
              </button>
              <button className="btn btn-sm btn-outline" onClick={() => setZoom(1)}>
                <RotateCw size={14} /> Reset
              </button>
            </div>
            <div className="toolbar-group">
              <button className={`btn btn-sm ${showSymbols ? 'btn-primary' : 'btn-outline'}`} onClick={() => setShowSymbols(!showSymbols)}>
                {showSymbols ? <Eye size={14} /> : <EyeOff size={14} />} Symbols
              </button>
            </div>
            <div className="toolbar-group">
              {Object.entries(SYSTEM_COLORS).map(([sys, color]) => (
                <button
                  key={sys}
                  className="btn btn-sm"
                  style={{
                    background: visibleSystems.has(sys) ? color : '#e2e8f0',
                    color: visibleSystems.has(sys) ? 'white' : '#94a3b8',
                    border: 'none',
                    padding: '3px 8px',
                    fontSize: 10,
                  }}
                  onClick={() => toggleSystem(sys)}
                >
                  {sys.replace('_', ' ').slice(0, 6)}
                </button>
              ))}
            </div>
          </div>

          {/* Drawing Canvas */}
          <div
            className="drawing-container"
            ref={canvasRef}
            onClick={handleCanvasClick}
            style={{ cursor: addingMode ? 'crosshair' : 'default', overflow: 'auto' }}
          >
            <img
              src={getDrawingImage(drawingId)}
              alt={drawing.filename}
              style={{ transform: `scale(${zoom})`, transformOrigin: 'top left', display: 'block' }}
            />

            {showSymbols && (
              <div className="symbol-overlay" style={{ transform: `scale(${zoom})`, transformOrigin: 'top left' }}>
                {placements
                  .filter(p => visibleSystems.has(p.system_type))
                  .map(p => (
                    <div
                      key={p.id}
                      className="placement-marker"
                      style={{ left: `${p.x * 100}%`, top: `${p.y * 100}%` }}
                      onClick={(e) => { e.stopPropagation(); setSelectedPlacement(p); }}
                    >
                      <div
                        className="marker-icon"
                        style={{ background: SYSTEM_COLORS[p.system_type] || '#666' }}
                      >
                        {SYMBOL_ICONS[p.symbol_code] || '\u25CF'}
                      </div>
                      <div className="marker-label">
                        {p.label || p.symbol_code} | {p.system_type.replace('_', ' ')}
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </div>

          {addingMode && (
            <div style={{ padding: 12, background: '#fef3c7', borderRadius: 8, marginTop: 8, fontSize: 13 }}>
              Click on the drawing to place: <strong>{addingMode.name}</strong> ({addingMode.system_type.replace('_', ' ')})
              <button className="btn btn-sm btn-outline" style={{ marginLeft: 12 }} onClick={() => setAddingMode(null)}>Cancel</button>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="panel-side">
          {/* Symbol Palette */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header"><h3><Layers size={16} /> Place Symbols</h3></div>
            <div className="card-body" style={{ padding: 12 }}>
              {Object.entries(SYSTEM_COLORS).map(([sys, color]) => (
                <div key={sys} style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color, marginBottom: 4, textTransform: 'uppercase' }}>
                    {sys.replace('_', ' ')}
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {Object.entries(SYMBOL_ICONS)
                      .filter(([code]) => {
                        const prefix = sys === 'cctv' ? 'CAM' : sys === 'access_control' ? 'AC' : sys === 'gate' ? 'GATE' : sys === 'fire' ? 'FIRE' : sys === 'sound' ? 'SND' : sys === 'video_door_phone' ? 'VDP' : '';
                        return code.startsWith(prefix);
                      })
                      .map(([code, icon]) => (
                        <button
                          key={code}
                          className="btn btn-sm"
                          style={{ background: addingMode?.code === code ? color : 'transparent', color: addingMode?.code === code ? 'white' : color, border: `1px solid ${color}`, padding: '3px 8px', fontSize: 11 }}
                          onClick={() => setAddingMode(addingMode?.code === code ? null : { code, system_type: sys, name: code })}
                          title={code}
                        >
                          {icon} {code.split('-')[1]}
                        </button>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Selected Placement Details */}
          {selectedPlacement && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-header">
                <h3>Selected Device</h3>
                <button className="modal-close" onClick={() => setSelectedPlacement(null)}>&times;</button>
              </div>
              <div className="card-body" style={{ fontSize: 13 }}>
                <p><strong>Symbol:</strong> {selectedPlacement.symbol_code}</p>
                <p><strong>System:</strong> <span className={`badge badge-${selectedPlacement.system_type}`}>{selectedPlacement.system_type.replace('_', ' ')}</span></p>
                <p><strong>Position:</strong> ({(selectedPlacement.x * 100).toFixed(1)}%, {(selectedPlacement.y * 100).toFixed(1)}%)</p>
                {selectedPlacement.label && <p><strong>Label:</strong> {selectedPlacement.label}</p>}
                {selectedPlacement.notes && <p><strong>Notes:</strong> {selectedPlacement.notes}</p>}
                <button className="btn btn-sm btn-accent" style={{ marginTop: 8 }} onClick={() => handleDeletePlacement(selectedPlacement.id)}>
                  <Trash2 size={12} /> Remove
                </button>
              </div>
            </div>
          )}

          {/* Analysis Results */}
          {analysis && !analysis.error && (
            <div className="card">
              <div className="card-header"><h3><CheckCircle size={16} /> AI Analysis</h3></div>
              <div className="card-body" style={{ fontSize: 13 }}>
                {analysis.summary && (
                  <div className="analysis-section">
                    <h4>Summary</h4>
                    <p>{analysis.summary}</p>
                  </div>
                )}
                {analysis.areas?.length > 0 && (
                  <div className="analysis-section">
                    <h4>Detected Areas ({analysis.areas.length})</h4>
                    {analysis.areas.map((area, i) => (
                      <div key={i} className="analysis-item">
                        <span className="tag">{area.type}</span>
                        <span>{area.name} ({area.area_sqm_estimate || '?'} sqm)</span>
                      </div>
                    ))}
                  </div>
                )}
                {analysis.suggested_products?.length > 0 && (
                  <div className="analysis-section">
                    <h4>Suggested Products ({analysis.suggested_products.length})</h4>
                    {analysis.suggested_products.map((p, i) => (
                      <div key={i} className="analysis-item" style={{ flexDirection: 'column', gap: 2 }}>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <span className={`badge badge-${p.system_type}`}>{p.system_type.replace('_', ' ')}</span>
                          <strong>{p.suggested_model}</strong>
                          <span>x{p.quantity}</span>
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-light)' }}>{p.reason}</div>
                      </div>
                    ))}
                  </div>
                )}
                {analysis.cable_runs?.length > 0 && (
                  <div className="analysis-section">
                    <h4>Cable Runs ({analysis.cable_runs.length})</h4>
                    {analysis.cable_runs.map((c, i) => (
                      <div key={i} className="analysis-item">
                        <span>{c.cable_type}: {c.estimated_length_m}m</span>
                        <span style={{ fontSize: 11, color: 'var(--text-light)' }}>({c.purpose})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Placements List */}
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header"><h3>Placements ({placements.length})</h3></div>
            <div className="card-body" style={{ padding: 0, maxHeight: 300, overflowY: 'auto' }}>
              {placements.length === 0 ? (
                <p style={{ padding: 16, color: 'var(--text-light)', fontSize: 13 }}>No devices placed yet</p>
              ) : (
                placements.map(p => (
                  <div
                    key={p.id}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
                      borderBottom: '1px solid var(--border-light)', cursor: 'pointer',
                      background: selectedPlacement?.id === p.id ? '#f0f4ff' : 'transparent',
                    }}
                    onClick={() => setSelectedPlacement(p)}
                  >
                    <div style={{
                      width: 24, height: 24, borderRadius: '50%',
                      background: SYSTEM_COLORS[p.system_type] || '#666',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      color: 'white', fontSize: 12, flexShrink: 0,
                    }}>
                      {SYMBOL_ICONS[p.symbol_code] || '\u25CF'}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600 }}>{p.label || p.symbol_code}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-light)' }}>{p.system_type.replace('_', ' ')}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {toast && <div className={`toast ${toast.type}`}>{toast.msg}</div>}
    </div>
  );
}
