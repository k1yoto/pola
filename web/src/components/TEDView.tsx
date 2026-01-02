import { useState, useEffect } from 'react';
import { getTED } from '../api/client';
import type { LsTED, LsNode } from '../types/api';
import TopologyMap from './TopologyMap';

const TEDView = () => {
  const [ted, setTED] = useState<LsTED | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'table' | 'topology'>('table');

  useEffect(() => {
    const fetchTED = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await getTED();
        console.log('TED Response:', response);
        console.log('TED data:', response.ted);
        console.log('TED.nodes:', response.ted?.nodes);
        setTED(response.ted);
      } catch (err) {
        console.error('TED fetch error:', err);
        setError(err instanceof Error ? err.message : 'Failed to fetch TED');
      } finally {
        setLoading(false);
      }
    };

    fetchTED();
  }, []);

  if (loading) {
    return (
      <div className="ted-view">
        <h2>Traffic Engineering Database (TED)</h2>
        <p>Loading TED...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="ted-view">
        <h2>Traffic Engineering Database (TED)</h2>
        <p className="error">Error: {error}</p>
      </div>
    );
  }

  if (!ted || !ted.nodes || Object.keys(ted.nodes).length === 0) {
    return (
      <div className="ted-view">
        <h2>Traffic Engineering Database (TED)</h2>
        <p>No TED data available</p>
      </div>
    );
  }

  // Flatten nodes for display
  const nodes: Array<{ asn: number; routerId: string; node: LsNode }> = [];
  Object.entries(ted.nodes).forEach(([asnStr, routerMap]) => {
    const asn = parseInt(asnStr, 10);
    Object.entries(routerMap).forEach(([routerId, node]) => {
      nodes.push({ asn, routerId, node });
    });
  });

  return (
    <div className="ted-view">
      <h2>Traffic Engineering Database (TED)</h2>

      <div className="ted-summary">
        <p>TED ID: {ted.id}</p>
        <p>Total Nodes: {nodes.length}</p>
      </div>

      <div className="view-mode-selector">
        <button
          className={viewMode === 'table' ? 'active' : ''}
          onClick={() => setViewMode('table')}
        >
          Table View
        </button>
        <button
          className={viewMode === 'topology' ? 'active' : ''}
          onClick={() => setViewMode('topology')}
        >
          Topology View
        </button>
      </div>

      {viewMode === 'table' ? (
        <table>
        <thead>
          <tr>
            <th>ASN</th>
            <th>Router ID</th>
            <th>Hostname</th>
            <th>ISIS Area ID</th>
            <th>SRGB</th>
            <th>Links</th>
            <th>Prefixes</th>
            <th>SRv6 SIDs</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map(({ asn, routerId, node }, index) => (
            <tr key={index}>
              <td>{asn}</td>
              <td className="monospace">{routerId}</td>
              <td>{node.hostname || '-'}</td>
              <td className="monospace">{node.isis_area_id || '-'}</td>
              <td>
                {node.srgb_begin && node.srgb_end ? (
                  <span className="srgb">
                    [{node.srgb_begin}, {node.srgb_end}]
                  </span>
                ) : (
                  '-'
                )}
              </td>
              <td>
                <span className="badge">{node.links ? node.links.length : 0}</span>
              </td>
              <td>
                <span className="badge">{node.prefixes ? node.prefixes.length : 0}</span>
              </td>
              <td>
                <span className="badge">{node.srv6_sids ? node.srv6_sids.length : 0}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      ) : (
        <TopologyMap ted={ted} />
      )}
    </div>
  );
};

export default TEDView;
