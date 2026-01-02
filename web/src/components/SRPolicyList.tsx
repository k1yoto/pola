import { useState, useEffect } from 'react';
import { getPolicies } from '../api/client';
import type { SRPolicy } from '../types/api';

const SRPolicyList = () => {
  const [policies, setPolicies] = useState<Record<string, SRPolicy[]>>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPolicies = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await getPolicies();
        setPolicies(response.policies || {});
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch policies');
      } finally {
        setLoading(false);
      }
    };

    fetchPolicies();
  }, []);

  if (loading) {
    return (
      <div className="policy-list">
        <h2>SR Policies</h2>
        <p>Loading policies...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="policy-list">
        <h2>SR Policies</h2>
        <p className="error">Error: {error}</p>
      </div>
    );
  }

  const peerAddresses = Object.keys(policies);

  if (peerAddresses.length === 0) {
    return (
      <div className="policy-list">
        <h2>SR Policies</h2>
        <p>No policies found</p>
      </div>
    );
  }

  return (
    <div className="policy-list">
      <h2>SR Policies</h2>
      {peerAddresses.map((peerAddr) => {
        const peerPolicies = policies[peerAddr];
        return (
          <div key={peerAddr} className="policy-group">
            <h3>Peer: {peerAddr}</h3>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Color</th>
                  <th>Preference</th>
                  <th>Segment List</th>
                </tr>
              </thead>
              <tbody>
                {peerPolicies.map((policy, index) => (
                  <tr key={index}>
                    <td>{policy.Name || '-'}</td>
                    <td>{policy.SrcAddr || '-'}</td>
                    <td>{policy.DstAddr || '-'}</td>
                    <td>
                      <span className="color-badge">{policy.Color}</span>
                    </td>
                    <td>{policy.Preference}</td>
                    <td>
                      {policy.SegmentList && policy.SegmentList.length > 0 ? (
                        <ul className="segment-list">
                          {policy.SegmentList.map((segment, idx) => (
                            <li key={idx} className="segment-item">
                              {segment.Sid}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span>-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
};

export default SRPolicyList;
