import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import ProjectView from './pages/ProjectView';
import DrawingView from './pages/DrawingView';
import ProductSearch from './pages/ProductSearch';
import './App.css';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/project/:projectId" element={<ProjectView />} />
          <Route path="/project/:projectId/drawing/:drawingId" element={<DrawingView />} />
          <Route path="/project/:projectId/products" element={<ProductSearch />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
