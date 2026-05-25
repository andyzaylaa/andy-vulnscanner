import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Search, ChevronRight, Plus, Globe, Database,
  Filter, ShoppingCart, Check, Package
} from 'lucide-react';
import {
  searchProducts, searchProductsOnline, addProductToProject,
  getProjectProducts
} from '../services/api';

const SYSTEM_TYPES = [
  { value: '', label: 'All Systems' },
  { value: 'cctv', label: 'CCTV / Surveillance' },
  { value: 'access_control', label: 'Access Control' },
  { value: 'gate', label: 'Gate / Barrier' },
  { value: 'video_door_phone', label: 'Video Door Phone' },
  { value: 'fire', label: 'Fire System' },
  { value: 'sound', label: 'Sound / PA' },
];

export default function ProductSearch() {
  const { projectId } = useParams();
  const [query, setQuery] = useState('');
  const [systemFilter, setSystemFilter] = useState('');
  const [results, setResults] = useState([]);
  const [onlineResults, setOnlineResults] = useState([]);
  const [projectProducts, setProjectProducts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeSource, setActiveSource] = useState('local');
  const [addingProduct, setAddingProduct] = useState(null);
  const [addForm, setAddForm] = useState({ quantity: 1, location_note: '', cable_type: '', cable_length_m: 0, notes: '' });
  const [toast, setToast] = useState(null);

  useEffect(() => {
    loadProjectProducts();
    handleSearch();
  }, []);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const loadProjectProducts = async () => {
    try {
      const res = await getProjectProducts(projectId);
      setProjectProducts(res.data);
    } catch {}
  };

  const handleSearch = async () => {
    setLoading(true);
    try {
      const res = await searchProducts({
        query,
        system_type: systemFilter || null,
        page: 1,
        per_page: 50,
      });
      setResults(res.data);
    } catch (err) {
      console.error('Search failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOnlineSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await searchProductsOnline(query);
      setOnlineResults(res.data.results || []);
    } catch (err) {
      console.error('Online search failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAddToProject = async (product) => {
    try {
      await addProductToProject(projectId, {
        product_id: product.id,
        quantity: addForm.quantity,
        system_type: product.system_type,
        location_note: addForm.location_note,
        cable_type: addForm.cable_type || product.cable_requirements?.type || '',
        cable_length_m: addForm.cable_length_m,
        notes: addForm.notes,
      });
      showToast(`Added ${product.model_number} to project`, 'success');
      setAddingProduct(null);
      setAddForm({ quantity: 1, location_note: '', cable_type: '', cable_length_m: 0, notes: '' });
      loadProjectProducts();
    } catch (err) {
      showToast('Failed to add product', 'error');
    }
  };

  const isInProject = (productId) => projectProducts.some(pp => pp.product_id === productId);

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="breadcrumb">
            <Link to="/">Projects</Link> <ChevronRight size={12} style={{ display: 'inline' }} />{' '}
            <Link to={`/project/${projectId}`}>Project</Link> <ChevronRight size={12} style={{ display: 'inline' }} /> Product Search
          </div>
          <h2>Search Products</h2>
        </div>
        <div className="btn-group">
          <span style={{ fontSize: 13, color: 'var(--text-light)' }}>
            <ShoppingCart size={14} style={{ display: 'inline' }} /> {projectProducts.length} products in project
          </span>
        </div>
      </div>

      {/* Search Bar */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-body">
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <div className="search-box" style={{ maxWidth: 'none', flex: 1 }}>
              <Search size={16} />
              <input
                type="text"
                placeholder="Search by model number, name, or description..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && (activeSource === 'local' ? handleSearch() : handleOnlineSearch())}
              />
            </div>
            <select className="form-control" style={{ width: 200 }} value={systemFilter} onChange={(e) => setSystemFilter(e.target.value)}>
              {SYSTEM_TYPES.map(st => <option key={st.value} value={st.value}>{st.label}</option>)}
            </select>
            <button className="btn btn-primary" onClick={activeSource === 'local' ? handleSearch : handleOnlineSearch}>
              <Search size={16} /> Search
            </button>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className={`btn btn-sm ${activeSource === 'local' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => { setActiveSource('local'); handleSearch(); }}
            >
              <Database size={14} /> Local Catalog ({results.length})
            </button>
            <button
              className={`btn btn-sm ${activeSource === 'online' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => { setActiveSource('online'); handleOnlineSearch(); }}
            >
              <Globe size={14} /> Hikvision Online
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {loading ? (
        <div className="loading"><div className="spinner" /> Searching products...</div>
      ) : activeSource === 'local' ? (
        results.length === 0 ? (
          <div className="empty-state">
            <Package size={48} />
            <h3>No products found</h3>
            <p>Try a different search term or filter</p>
          </div>
        ) : (
          <div className="grid grid-2">
            {results.map(product => (
              <div key={product.id} className="card product-card">
                <div className="card-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div className="product-model">{product.model_number}</div>
                      <div className="product-name">{product.name}</div>
                    </div>
                    <span className={`badge badge-${product.system_type}`}>{product.system_type.replace('_', ' ')}</span>
                  </div>

                  <p style={{ fontSize: 12, color: 'var(--text-light)', margin: '8px 0' }}>{product.description}</p>

                  {product.specifications && Object.keys(product.specifications).length > 0 && (
                    <div className="product-specs">
                      {Object.entries(product.specifications).slice(0, 4).map(([k, v]) => (
                        <span key={k} className="tag" style={{ marginRight: 4, marginBottom: 4 }}>
                          {k.replace('_', ' ')}: {String(v)}
                        </span>
                      ))}
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
                    <span className="product-price">${product.price?.toFixed(2)}</span>
                    <div className="btn-group">
                      {isInProject(product.id) ? (
                        <span className="tag" style={{ color: 'var(--success)' }}><Check size={12} /> In project</span>
                      ) : null}
                      <button className="btn btn-sm btn-primary" onClick={() => setAddingProduct(product)}>
                        <Plus size={12} /> Add to Project
                      </button>
                    </div>
                  </div>

                  {product.accessories?.length > 0 && (
                    <div style={{ marginTop: 8, padding: '8px 0', borderTop: '1px solid var(--border-light)' }}>
                      <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 4 }}>Included Accessories:</div>
                      {product.accessories.map((acc, i) => (
                        <span key={i} className="tag" style={{ marginRight: 4, marginBottom: 2, fontSize: 10 }}>
                          {acc.name} ({acc.model})
                        </span>
                      ))}
                    </div>
                  )}

                  {product.cable_requirements?.type && (
                    <div style={{ fontSize: 11, color: 'var(--text-light)', marginTop: 4 }}>
                      Cable: {product.cable_requirements.type}
                      {product.cable_requirements.poe && ' (PoE)'}
                      {product.cable_requirements.max_length_m && ` | Max ${product.cable_requirements.max_length_m}m`}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        /* Online Results */
        onlineResults.length === 0 ? (
          <div className="empty-state">
            <Globe size={48} />
            <h3>No online results</h3>
            <p>Enter a search term and click Search to find products on Hikvision.com</p>
          </div>
        ) : (
          <div className="grid grid-2">
            {onlineResults.map((r, i) => (
              <div key={i} className="card product-card">
                <div className="card-body">
                  <div className="product-model">{r.model_number || 'Unknown Model'}</div>
                  <div className="product-name">{r.name}</div>
                  <p style={{ fontSize: 12, color: 'var(--text-light)', margin: '8px 0' }}>{r.description}</p>
                  {r.url && (
                    <a href={r.url} target="_blank" rel="noopener noreferrer" className="btn btn-sm btn-outline">
                      <Globe size={12} /> View on Hikvision.com
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        )
      )}

      {/* Add to Project Modal */}
      {addingProduct && (
        <div className="modal-overlay" onClick={() => setAddingProduct(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add to Project</h3>
              <button className="modal-close" onClick={() => setAddingProduct(null)}>&times;</button>
            </div>
            <div className="modal-body">
              <div style={{ padding: 12, background: '#f8fafc', borderRadius: 8, marginBottom: 16 }}>
                <strong>{addingProduct.model_number}</strong>
                <br />
                <span style={{ fontSize: 13 }}>{addingProduct.name}</span>
                <br />
                <span className={`badge badge-${addingProduct.system_type}`} style={{ marginTop: 4 }}>
                  {addingProduct.system_type.replace('_', ' ')}
                </span>
              </div>

              <div className="form-group">
                <label>Quantity</label>
                <input
                  type="number" className="form-control" min="1"
                  value={addForm.quantity}
                  onChange={e => setAddForm({ ...addForm, quantity: parseInt(e.target.value) || 1 })}
                />
              </div>
              <div className="form-group">
                <label>Location / Area</label>
                <input
                  className="form-control" placeholder="e.g., Main Entrance, Office Area A"
                  value={addForm.location_note}
                  onChange={e => setAddForm({ ...addForm, location_note: e.target.value })}
                />
              </div>
              <div className="grid grid-2">
                <div className="form-group">
                  <label>Cable Type</label>
                  <input
                    className="form-control" placeholder={addingProduct.cable_requirements?.type || 'e.g., CAT6 UTP'}
                    value={addForm.cable_type}
                    onChange={e => setAddForm({ ...addForm, cable_type: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Cable Length (m)</label>
                  <input
                    type="number" className="form-control" min="0"
                    value={addForm.cable_length_m}
                    onChange={e => setAddForm({ ...addForm, cable_length_m: parseFloat(e.target.value) || 0 })}
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Notes</label>
                <textarea
                  className="form-control" rows={2} placeholder="Additional notes..."
                  value={addForm.notes}
                  onChange={e => setAddForm({ ...addForm, notes: e.target.value })}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-outline" onClick={() => setAddingProduct(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={() => handleAddToProject(addingProduct)}>
                <Plus size={16} /> Add to Project (${(addingProduct.price * addForm.quantity).toFixed(2)})
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className={`toast ${toast.type}`}>{toast.msg}</div>}
    </div>
  );
}
