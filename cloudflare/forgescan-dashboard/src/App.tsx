import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from '@/components/layout/Layout';
import { Dashboard } from '@/pages/Dashboard';
import { Assets } from '@/pages/Assets';
import { Findings } from '@/pages/Findings';
import { Scans } from '@/pages/Scans';
import { Import } from '@/pages/Import';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="assets" element={<Assets />} />
          <Route path="findings" element={<Findings />} />
          <Route path="scans" element={<Scans />} />
          <Route path="import" element={<Import />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
