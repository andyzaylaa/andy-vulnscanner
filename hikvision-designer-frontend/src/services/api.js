import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

// Projects
export const createProject = (data) => api.post('/api/projects', data);
export const listProjects = () => api.get('/api/projects');
export const getProject = (id) => api.get(`/api/projects/${id}`);
export const updateProject = (id, data) => api.put(`/api/projects/${id}`, data);
export const deleteProject = (id) => api.delete(`/api/projects/${id}`);

// Drawings
export const uploadDrawing = (projectId, file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post(`/api/drawings/upload/${projectId}`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};
export const listDrawings = (projectId) => api.get(`/api/drawings/project/${projectId}`);
export const getDrawingImage = (drawingId) => `${API_BASE}/api/drawings/${drawingId}/image`;
export const analyzeDrawing = (drawingId) => api.post(`/api/drawings/${drawingId}/analyze`);
export const getDrawingPlacements = (drawingId) => api.get(`/api/drawings/${drawingId}/placements`);
export const addPlacement = (data) => api.post('/api/drawings/placements', data);
export const deletePlacement = (id) => api.delete(`/api/drawings/placements/${id}`);

// Products
export const searchProducts = (query) => api.post('/api/products/search', query);
export const searchProductsOnline = (q) => api.get(`/api/products/search-online?q=${encodeURIComponent(q)}`);
export const getProduct = (id) => api.get(`/api/products/${id}`);
export const createProduct = (data) => api.post('/api/products', data);
export const getSystemTypes = () => api.get('/api/products/system-types');
export const getCategories = () => api.get('/api/products/categories');

// Project Products
export const addProductToProject = (projectId, data) => api.post(`/api/products/project/${projectId}`, data);
export const getProjectProducts = (projectId) => api.get(`/api/products/project/${projectId}`);
export const removeProjectProduct = (ppId) => api.delete(`/api/products/project-product/${ppId}`);

// BOQ
export const uploadBOQ = (projectId, file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post(`/api/boq/upload/${projectId}`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};
export const getBOQEntries = (projectId) => api.get(`/api/boq/${projectId}`);

// Reports
export const calculateCables = (projectId) => api.get(`/api/reports/${projectId}/cables`);
export const calculateAccessories = (projectId) => api.get(`/api/reports/${projectId}/accessories`);
export const downloadExcelReport = (projectId) => 
  api.get(`/api/reports/${projectId}/excel`, { responseType: 'blob' });
export const getProjectSummary = (projectId) => api.get(`/api/reports/${projectId}/summary`);

// Symbols
export const getSymbolLibrary = () => api.get('/api/symbols');

export default api;
