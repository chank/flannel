// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//go:build !windows
// +build !windows

package geneve

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/flannel-io/flannel/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/subnet"
	"golang.org/x/net/context"
	log "k8s.io/klog"
)

func init() {
	backend.Register("geneve", New)
}

const (
	defaultVNI = 1
)

type GeneveBackend struct {
	subnetMgr subnet.Manager
	extIface  *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	backend := &GeneveBackend{
		subnetMgr: sm,
		extIface:  extIface,
	}

	return backend, nil
}

func newSubnetAttrs(publicIP net.IP, publicIPv6 net.IP, vnid uint16, dev, v6Dev *geneveDevice) (*subnet.LeaseAttrs, error) {
	leaseAttrs := &subnet.LeaseAttrs{
		BackendType: "geneve",
	}
	if publicIP != nil && dev != nil {
		data, err := json.Marshal(&geneveLeaseAttrs{
			VNI:     vnid,
			VtepMAC: hardwareAddr(dev.MACAddr()),
		})
		if err != nil {
			return nil, err
		}
		leaseAttrs.PublicIP = ip.FromIP(publicIP)
		leaseAttrs.BackendData = json.RawMessage(data)
	}

	if publicIPv6 != nil && v6Dev != nil {
		data, err := json.Marshal(&geneveLeaseAttrs{
			VNI:     vnid,
			VtepMAC: hardwareAddr(v6Dev.MACAddr()),
		})
		if err != nil {
			return nil, err
		}
		leaseAttrs.PublicIPv6 = ip.FromIP6(publicIPv6)
		leaseAttrs.BackendV6Data = json.RawMessage(data)
	}
	return leaseAttrs, nil
}

func (be *GeneveBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	// Parse our configuration
	cfg := struct {
		VNI           int
		Port          int
		GBP           bool
		Learning      bool
		DirectRouting bool
	}{
		VNI: defaultVNI,
	}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding Geneve backend config: %v", err)
		}
	}
	log.Infof("Geneve config: VNI=%d Port=%d GBP=%v Learning=%v DirectRouting=%v", cfg.VNI, cfg.Port, cfg.GBP, cfg.Learning, cfg.DirectRouting)

	var dev, v6Dev *geneveDevice
	var err error
	if config.EnableIPv4 {
		devAttrs := geneveDeviceAttrs{
			vni:       uint32(cfg.VNI),
			name:      fmt.Sprintf("flannel.%v", cfg.VNI),
			vtepIndex: be.extIface.Iface.Index,
			vtepAddr:  be.extIface.IfaceAddr,
			vtepPort:  cfg.Port,
			gbp:       cfg.GBP,
			learning:  cfg.Learning,
		}

		dev, err = newGeneveDevice(&devAttrs)
		if err != nil {
			return nil, err
		}
		dev.directRouting = cfg.DirectRouting
	}
	if config.EnableIPv6 {
		v6DevAttrs := geneveDeviceAttrs{
			vni:       uint32(cfg.VNI),
			name:      fmt.Sprintf("flannel-v6.%v", cfg.VNI),
			vtepIndex: be.extIface.Iface.Index,
			vtepAddr:  be.extIface.IfaceV6Addr,
			vtepPort:  cfg.Port,
			gbp:       cfg.GBP,
			learning:  cfg.Learning,
		}
		v6Dev, err = newGeneveDevice(&v6DevAttrs)
		if err != nil {
			return nil, err
		}
		v6Dev.directRouting = cfg.DirectRouting
	}

	subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, be.extIface.ExtV6Addr, uint16(cfg.VNI), dev, v6Dev)
	if err != nil {
		return nil, err
	}

	lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
	switch err {
	case nil:
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Ensure that the device has a /32 address so that no broadcast routes are created.
	// This IP is just used as a source address for host to workload traffic (so
	// the return path for the traffic has an address on the flannel network to use as the destination)
	if config.EnableIPv4 {
		if err := dev.Configure(ip.IP4Net{IP: lease.Subnet.IP, PrefixLen: 32}, config.Network); err != nil {
			return nil, fmt.Errorf("failed to configure interface %s: %w", dev.link.Attrs().Name, err)
		}
	}
	if config.EnableIPv6 {
		if err := v6Dev.ConfigureIPv6(ip.IP6Net{IP: lease.IPv6Subnet.IP, PrefixLen: 128}, config.IPv6Network); err != nil {
			return nil, fmt.Errorf("failed to configure interface %s: %w", v6Dev.link.Attrs().Name, err)
		}
	}
	return newNetwork(be.subnetMgr, be.extIface, dev, v6Dev, ip.IP4Net{}, lease)
}

// So we can make it JSON (un)marshalable
type hardwareAddr net.HardwareAddr

func (hw hardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", net.HardwareAddr(hw))), nil
}

func (hw *hardwareAddr) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("error parsing hardware addr")
	}

	bytes = bytes[1 : len(bytes)-1]

	mac, err := net.ParseMAC(string(bytes))
	if err != nil {
		return err
	}

	*hw = hardwareAddr(mac)
	return nil
}
