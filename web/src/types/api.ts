// API型定義

export interface Session {
  Addr: string;
  State: string;
  Caps: string[];
  IsSynced: boolean;
}

export interface SessionsResponse {
  sessions: Session[];
}

export interface Segment {
  Sid: string;
}

export interface SRPolicy {
  Name: string;
  SegmentList: Segment[];
  SrcAddr: string;
  DstAddr: string;
  Color: number;
  Preference: number;
}

export interface PoliciesResponse {
  policies: Record<string, SRPolicy[]>;
}

export interface Metric {
  type: number;
  value: number;
}

export interface Srv6EndXSID {
  endpoint_behavior: number;
  sids: string[];
  srv6_sid_structure: SIDStructure;
}

export interface SIDStructure {
  local_block: number;
  local_node: number;
  local_func: number;
  local_arg: number;
}

export interface LsLink {
  remote_router_id: string;
  remote_asn: number;
  local_ip: string;
  remote_ip: string;
  metrics: Metric[];
  adj_sid: number;
  srv6_endx_sid?: Srv6EndXSID;
}

export interface LsPrefix {
  prefix: string;
  sid_index: number;
}

export interface LsSrv6SID {
  sids: string[];
  endpoint_behavior: {
    behavior: number;
    flags: number;
    algorithm: number;
  };
  sid_structure: SIDStructure;
  bgp_peer_node_sid?: {
    flags: number;
    weight: number;
    peer_asn: number;
    peer_bgp_id: string;
  };
  multi_topo_ids: number[];
  service_type: number;
  traffic_type: number;
  opaque_type: number;
  value: string | null;
}

export interface LsNode {
  asn: number;
  router_id: string;
  hostname: string;
  isis_area_id: string;
  srgb_begin: number;
  srgb_end: number;
  links: LsLink[];
  prefixes: LsPrefix[];
  srv6_sids: LsSrv6SID[];
}

export interface LsTED {
  id: number;
  nodes: Record<number, Record<string, LsNode>>;
}

export interface TEDResponse {
  ted: LsTED;
}

export interface ErrorResponse {
  error: string;
}
