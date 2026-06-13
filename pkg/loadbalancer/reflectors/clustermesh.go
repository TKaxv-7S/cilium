// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/stream"

	cmendpointslice "github.com/cilium/cilium/pkg/clustermesh/endpointslice"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
)

type clusterMeshEndpointSliceObserver struct {
	log *slog.Logger
	ch  clusterMeshEndpointSliceEvents
}

type clusterMeshEndpointSliceEvents chan event

func newClusterMeshEndpointSliceEvents() clusterMeshEndpointSliceEvents {
	return make(clusterMeshEndpointSliceEvents)
}

func (c clusterMeshEndpointSliceEvents) Observe(ctx context.Context, next func(event), complete func(error)) {
	stream.FromChannel((<-chan event)(c)).Observe(ctx, next, complete)
}

func newClusterMeshEndpointSliceObserver(log *slog.Logger, events clusterMeshEndpointSliceEvents, cs client.Clientset, w *writer.Writer) cmendpointslice.Observer {
	if !cs.IsEnabled() || !w.IsEnabled() {
		return nil
	}
	return &clusterMeshEndpointSliceObserver{
		log: log,
		ch:  events,
	}
}

func (o *clusterMeshEndpointSliceObserver) OnUpdate(k store.Key) {
	eps, ok := k.(*endpointslicetypes.ValidatingClusterEndpointSlice)
	if !ok {
		return
	}
	o.ch <- upsertEndpointEvent{
		source:    source.ClusterMesh,
		clusterID: eps.ClusterID,
		obj:       toK8sEndpoints(o.log, &eps.ClusterEndpointSlice),
	}
}

func (o *clusterMeshEndpointSliceObserver) OnDelete(k store.NamedKey) {
	eps, ok := k.(*endpointslicetypes.ValidatingClusterEndpointSlice)
	if !ok {
		return
	}
	o.ch <- deleteEndpointEvent{
		source:    source.ClusterMesh,
		clusterID: eps.ClusterID,
		obj:       toK8sEndpoints(o.log, &eps.ClusterEndpointSlice),
	}
}

func toK8sEndpoints(log *slog.Logger, eps *endpointslicetypes.ClusterEndpointSlice) *k8s.Endpoints {
	obj := &slim_discoveryv1.EndpointSlice{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        eps.Name,
			Namespace:   eps.Namespace,
			Labels:      eps.Labels,
			Annotations: eps.Annotations,
		},
		AddressType: eps.AddressType,
		Endpoints:   slices.Clone(eps.Endpoints),
		Ports:       eps.Ports,
	}
	for i := range obj.Endpoints {
		obj.Endpoints[i].Addresses = slices.Clone(obj.Endpoints[i].Addresses)
		for j, address := range obj.Endpoints[i].Addresses {
			addr, err := netip.ParseAddr(address)
			if err != nil {
				continue
			}
			obj.Endpoints[i].Addresses[j] = cmtypes.AddrClusterFrom(addr, eps.ClusterID).String()
		}
	}
	return k8s.ParseEndpointSliceV1(log, obj)
}
