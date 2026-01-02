import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core, ElementDefinition } from 'cytoscape';
// @ts-expect-error cytoscape-cola has no type definitions
import cola from 'cytoscape-cola';
import type { LsTED } from '../types/api';

// Register cola layout
cytoscape.use(cola);

interface TopologyMapProps {
  ted: LsTED;
}

const TopologyMap = ({ ted }: TopologyMapProps) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current || !ted || !ted.nodes) {
      return;
    }

    // Convert TED data to Cytoscape elements
    const elements: ElementDefinition[] = [];

    // Create nodes
    Object.entries(ted.nodes).forEach(([asnStr, routerMap]) => {
      const asn = parseInt(asnStr, 10);
      Object.entries(routerMap).forEach(([routerId, node]) => {
        elements.push({
          data: {
            id: `${asn}-${routerId}`,
            label: node.hostname || routerId,
            asn: asn,
            routerId: routerId,
            hostname: node.hostname,
            isisAreaId: node.isis_area_id,
            srgbBegin: node.srgb_begin,
            srgbEnd: node.srgb_end,
            linksCount: node.links?.length || 0,
            prefixesCount: node.prefixes?.length || 0,
            srv6SidsCount: node.srv6_sids?.length || 0,
          },
        });

        // Create edges from links
        if (node.links) {
          node.links.forEach((link, linkIndex) => {
            // Use remote_router_id and remote_asn from link
            const remoteNodeId = `${link.remote_asn}-${link.remote_router_id}`;
            const sourceId = `${asn}-${routerId}`;

            // Only create edge if source < target to avoid duplicates (bidirectional links)
            if (sourceId < remoteNodeId) {
              const metrics = link.metrics || [];
              const igpMetric = metrics.find((m) => m.type === 0)?.value || 0;
              const teMetric = metrics.find((m) => m.type === 1)?.value || 0;
              const delayMetric = metrics.find((m) => m.type === 2)?.value || 0;

              elements.push({
                data: {
                  id: `${sourceId}-${remoteNodeId}-${linkIndex}`,
                  source: sourceId,
                  target: remoteNodeId,
                  localIp: link.local_ip,
                  remoteIp: link.remote_ip,
                  igpMetric: igpMetric,
                  teMetric: teMetric,
                  delayMetric: delayMetric,
                  adjSid: link.adj_sid,
                  srv6EndXSid: link.srv6_endx_sid?.sids?.[0] || '',
                },
              });
            }
          });
        }
      });
    });

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#2563eb',
            label: 'data(label)',
            color: '#fff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': '12px',
            'font-weight': 'bold',
            width: 60,
            height: 60,
            'border-width': 2,
            'border-color': '#1e40af',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 3,
            'line-color': '#94a3b8',
            'target-arrow-color': '#94a3b8',
            'target-arrow-shape': 'none',
            'curve-style': 'bezier',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'background-color': '#dc2626',
            'border-color': '#991b1b',
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#dc2626',
            width: 5,
          },
        },
      ],
      layout: {
        name: 'cola',
        fit: true,
        padding: 30,
        nodeDimensionsIncludeLabels: true,
        randomize: false,
        avoidOverlap: true,
        handleDisconnected: true,
        nodeSpacing: 50,
        edgeLength: 100,
      } as any, // Cola layout has additional options not in base type
      minZoom: 0.1,
      maxZoom: 3,
    });

    // Add tooltips on hover
    cy.on('mouseover', 'node', (event) => {
      const node = event.target;
      const data = node.data();
      const tooltip = `
ASN: ${data.asn}
Router ID: ${data.routerId}
Hostname: ${data.hostname || 'N/A'}
ISIS Area: ${data.isisAreaId || 'N/A'}
SRGB: [${data.srgbBegin}, ${data.srgbEnd}]
Links: ${data.linksCount}
Prefixes: ${data.prefixesCount}
SRv6 SIDs: ${data.srv6SidsCount}
      `.trim();

      node.data('tooltip', tooltip);
      console.log(tooltip);
    });

    cy.on('mouseover', 'edge', (event) => {
      const edge = event.target;
      const data = edge.data();
      const tooltip = `
Link: ${data.source} ↔ ${data.target}
Local IP: ${data.localIp || 'N/A'}
Remote IP: ${data.remoteIp || 'N/A'}
IGP Metric: ${data.igpMetric}
TE Metric: ${data.teMetric}
Delay Metric: ${data.delayMetric}
SRv6 End.X SID: ${data.srv6EndXSid || 'N/A'}
      `.trim();

      console.log(tooltip);
    });

    cyRef.current = cy;

    // Cleanup
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [ted]);

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: '600px',
        border: '1px solid #e2e8f0',
        borderRadius: '8px',
        backgroundColor: '#f8fafc',
      }}
    />
  );
};

export default TopologyMap;
