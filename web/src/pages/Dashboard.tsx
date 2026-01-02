import { useState } from 'react';
import SessionList from '../components/SessionList';
import SRPolicyList from '../components/SRPolicyList';
import TEDView from '../components/TEDView';
import PolicyEditor from '../components/PolicyEditor';

const Dashboard = () => {
  const [refreshKey, setRefreshKey] = useState<number>(0);

  const handlePolicyChange = () => {
    // Trigger refresh of SRPolicyList by changing the key
    setRefreshKey((prev) => prev + 1);
  };

  return (
    <div className="dashboard">
      <SessionList />
      <PolicyEditor
        onPolicyCreated={handlePolicyChange}
        onPolicyDeleted={handlePolicyChange}
      />
      <SRPolicyList key={refreshKey} />
      <TEDView />
    </div>
  );
};

export default Dashboard;
