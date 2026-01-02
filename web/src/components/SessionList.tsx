import { useState, useEffect } from 'react';
import { getSessions } from '../api/client';
import type { Session } from '../types/api';

const SessionList = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await getSessions();
        setSessions(response.sessions || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch sessions');
      } finally {
        setLoading(false);
      }
    };

    fetchSessions();
  }, []);

  if (loading) {
    return (
      <div className="session-list">
        <h2>PCEP Sessions</h2>
        <p>Loading sessions...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="session-list">
        <h2>PCEP Sessions</h2>
        <p className="error">Error: {error}</p>
      </div>
    );
  }

  if (sessions.length === 0) {
    return (
      <div className="session-list">
        <h2>PCEP Sessions</h2>
        <p>No sessions found</p>
      </div>
    );
  }

  return (
    <div className="session-list">
      <h2>PCEP Sessions</h2>
      <table>
        <thead>
          <tr>
            <th>Address</th>
            <th>State</th>
            <th>Capabilities</th>
            <th>Synced</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session, index) => (
            <tr key={index}>
              <td>{session.Addr}</td>
              <td>
                <span className={`status ${session.State.toLowerCase()}`}>
                  {session.State}
                </span>
              </td>
              <td>
                {session.Caps && session.Caps.length > 0 ? (
                  <ul className="caps-list">
                    {session.Caps.map((cap, idx) => (
                      <li key={idx}>{cap}</li>
                    ))}
                  </ul>
                ) : (
                  <span>-</span>
                )}
              </td>
              <td>
                <span className={session.IsSynced ? 'synced' : 'not-synced'}>
                  {session.IsSynced ? '✓' : '✗'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default SessionList;
