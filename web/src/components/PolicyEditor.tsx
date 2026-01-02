import { useState } from 'react';
import type { SRPolicy } from '../types/api';

interface PolicyEditorProps {
  onPolicyCreated?: (policy: SRPolicy) => void;
  onPolicyDeleted?: () => void;
}

// API base URL - use environment variable if set, otherwise use empty string for same-origin
const envApiUrl = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = envApiUrl !== undefined ? envApiUrl : 'http://localhost:8080';

interface CreatePolicyForm {
  peer_addr: string;
  name: string;
  src_addr: string;          // For explicit path
  dst_addr: string;          // For explicit path
  src_router_id: string;     // For dynamic path
  dst_router_id: string;     // For dynamic path
  color: number;
  preference: number;
  segment_list: string;
  is_dynamic: boolean;
  metric_type: number;
  asn: number;
}

interface DeletePolicyForm {
  peer_addr: string;
  dst_addr: string;
  name: string;
  color: number;
  asn: number;
}

const PolicyEditor = ({ onPolicyCreated, onPolicyDeleted }: PolicyEditorProps) => {
  const [mode, setMode] = useState<'create' | 'delete'>('create');
  const [isDynamic, setIsDynamic] = useState<boolean>(false);
  const [createForm, setCreateForm] = useState<CreatePolicyForm>({
    peer_addr: '',
    name: '',
    src_addr: '',
    dst_addr: '',
    src_router_id: '',
    dst_router_id: '',
    color: 0,
    preference: 100,
    segment_list: '',
    is_dynamic: false,
    metric_type: 1,
    asn: 65000,
  });
  const [deleteForm, setDeleteForm] = useState<DeletePolicyForm>({
    peer_addr: '',
    dst_addr: '',
    name: '',
    color: 0,
    asn: 65000,
  });
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/policies`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...createForm,
          segment_list: createForm.segment_list
            ? createForm.segment_list.split(',').map((s) => s.trim()).filter((s) => s)
            : [],
          is_dynamic: isDynamic,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create SR policy');
      }

      const data = await response.json();
      setSuccess('SR policy created successfully');

      // Reset form
      setCreateForm({
        peer_addr: '',
        name: '',
        src_addr: '',
        dst_addr: '',
        src_router_id: '',
        dst_router_id: '',
        color: 0,
        preference: 100,
        segment_list: '',
        is_dynamic: false,
        metric_type: 1,
        asn: 65000,
      });
      setIsDynamic(false);

      if (onPolicyCreated && data.policy) {
        onPolicyCreated(data.policy);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create SR policy');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!window.confirm(`Are you sure you want to delete SR policy "${deleteForm.name}"?`)) {
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/policies`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(deleteForm),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete SR policy');
      }

      setSuccess('SR policy deleted successfully');

      // Reset form
      setDeleteForm({
        peer_addr: '',
        dst_addr: '',
        name: '',
        color: 0,
        asn: 65000,
      });

      if (onPolicyDeleted) {
        onPolicyDeleted();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete SR policy');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="policy-editor">
      <h2>SR Policy Management</h2>

      <div className="mode-selector">
        <button
          className={mode === 'create' ? 'active' : ''}
          onClick={() => setMode('create')}
        >
          Create Policy
        </button>
        <button
          className={mode === 'delete' ? 'active' : ''}
          onClick={() => setMode('delete')}
        >
          Delete Policy
        </button>
      </div>

      {error && <div className="notification error">{error}</div>}
      {success && <div className="notification success">{success}</div>}

      {mode === 'create' ? (
        <form onSubmit={handleCreateSubmit} className="policy-form">
          <div className="form-group">
            <label htmlFor="peer_addr">Peer Address *</label>
            <input
              type="text"
              id="peer_addr"
              value={createForm.peer_addr}
              onChange={(e) => setCreateForm({ ...createForm, peer_addr: e.target.value })}
              placeholder="e.g., 10.0.0.1"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="name">Policy Name *</label>
            <input
              type="text"
              id="name"
              value={createForm.name}
              onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
              placeholder="e.g., policy1"
              required
            />
          </div>

          {isDynamic ? (
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="src_router_id">Source Router ID *</label>
                <input
                  type="text"
                  id="src_router_id"
                  value={createForm.src_router_id}
                  onChange={(e) => setCreateForm({ ...createForm, src_router_id: e.target.value })}
                  placeholder="e.g., 0000.0000.0001"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="dst_router_id">Destination Router ID *</label>
                <input
                  type="text"
                  id="dst_router_id"
                  value={createForm.dst_router_id}
                  onChange={(e) => setCreateForm({ ...createForm, dst_router_id: e.target.value })}
                  placeholder="e.g., 0000.0000.0002"
                  required
                />
              </div>
            </div>
          ) : (
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="src_addr">Source Address *</label>
                <input
                  type="text"
                  id="src_addr"
                  value={createForm.src_addr}
                  onChange={(e) => setCreateForm({ ...createForm, src_addr: e.target.value })}
                  placeholder="e.g., fc00:0:1::1"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="dst_addr">Destination Address *</label>
                <input
                  type="text"
                  id="dst_addr"
                  value={createForm.dst_addr}
                  onChange={(e) => setCreateForm({ ...createForm, dst_addr: e.target.value })}
                  placeholder="e.g., fc00:0:2::1"
                  required
                />
              </div>
            </div>
          )}

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="color">Color *</label>
              <input
                type="number"
                id="color"
                value={createForm.color}
                onChange={(e) => setCreateForm({ ...createForm, color: parseInt(e.target.value) })}
                min="0"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="preference">Preference *</label>
              <input
                type="number"
                id="preference"
                value={createForm.preference}
                onChange={(e) => setCreateForm({ ...createForm, preference: parseInt(e.target.value) })}
                min="0"
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="asn">ASN *</label>
            <input
              type="number"
              id="asn"
              value={createForm.asn}
              onChange={(e) => setCreateForm({ ...createForm, asn: parseInt(e.target.value) })}
              min="0"
              placeholder="e.g., 65000"
              required
            />
          </div>

          <div className="form-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={isDynamic}
                onChange={(e) => {
                  setIsDynamic(e.target.checked);
                  setCreateForm({ ...createForm, is_dynamic: e.target.checked });
                }}
              />
              Dynamic Path Computation
            </label>
          </div>

          {isDynamic && (
            <div className="form-group">
              <label htmlFor="metric_type">Metric Type</label>
              <select
                id="metric_type"
                value={createForm.metric_type}
                onChange={(e) => setCreateForm({ ...createForm, metric_type: parseInt(e.target.value) })}
              >
                <option value="1">IGP Metric</option>
                <option value="2">TE Metric</option>
                <option value="3">Delay</option>
              </select>
            </div>
          )}

          {!isDynamic && (
            <div className="form-group">
              <label htmlFor="segment_list">Segment List (comma-separated)</label>
              <input
                type="text"
                id="segment_list"
                value={createForm.segment_list}
                onChange={(e) => setCreateForm({ ...createForm, segment_list: e.target.value })}
                placeholder="e.g., fc00:0:1::1, fc00:0:2::1, fc00:0:3::1"
              />
              <small>Enter SIDs separated by commas for explicit path</small>
            </div>
          )}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Creating...' : 'Create SR Policy'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleDeleteSubmit} className="policy-form">
          <div className="form-group">
            <label htmlFor="delete_peer_addr">Peer Address *</label>
            <input
              type="text"
              id="delete_peer_addr"
              value={deleteForm.peer_addr}
              onChange={(e) => setDeleteForm({ ...deleteForm, peer_addr: e.target.value })}
              placeholder="e.g., fc00:0:1::1"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="delete_dst_addr">Destination Address *</label>
            <input
              type="text"
              id="delete_dst_addr"
              value={deleteForm.dst_addr}
              onChange={(e) => setDeleteForm({ ...deleteForm, dst_addr: e.target.value })}
              placeholder="e.g., fc00:0:2::1"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="delete_name">Policy Name *</label>
            <input
              type="text"
              id="delete_name"
              value={deleteForm.name}
              onChange={(e) => setDeleteForm({ ...deleteForm, name: e.target.value })}
              placeholder="e.g., policy1"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="delete_color">Color *</label>
            <input
              type="number"
              id="delete_color"
              value={deleteForm.color}
              onChange={(e) => setDeleteForm({ ...deleteForm, color: parseInt(e.target.value) })}
              min="0"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="delete_asn">ASN *</label>
            <input
              type="number"
              id="delete_asn"
              value={deleteForm.asn}
              onChange={(e) => setDeleteForm({ ...deleteForm, asn: parseInt(e.target.value) })}
              min="0"
              placeholder="e.g., 65000"
              required
            />
          </div>

          <button type="submit" disabled={loading} className="submit-button delete">
            {loading ? 'Deleting...' : 'Delete SR Policy'}
          </button>
        </form>
      )}
    </div>
  );
};

export default PolicyEditor;
