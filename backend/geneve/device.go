//go:build !windows
// +build !windows

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

package geneve

import (
	"fmt"
	"net"
	"syscall"

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/mac"
	"github.com/vishvananda/netlink"
	log "k8s.io/klog"
)

type geneveDeviceAttrs struct {
	vni       uint32
	name      string
	vtepIndex int
	vtepAddr  net.IP
	vtepPort  int
	gbp       bool
	learning  bool
}

type geneveDevice struct {
	link          *netlink.Geneve
	directRouting bool
}

func newGeneveDevice(devAttrs *geneveDeviceAttrs) (*geneveDevice, error) {
	hardwareAddr, err := mac.NewHardwareAddr()
	if err != nil {
		return nil, err
	}

	link := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         devAttrs.name,
			HardwareAddr: hardwareAddr,
		},
		ID:      devAttrs.vni,
	}

	link, err = ensureLink(link)
	if err != nil {
		return nil, err
	}

	_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", devAttrs.name), "0")

	return &geneveDevice{
		link: link,
	}, nil
}

func ensureLink(geneve *netlink.Geneve) (*netlink.Geneve, error) {
	err := netlink.LinkAdd(geneve)
	if err == syscall.EEXIST {
		// it's ok if the device already exists as long as config is similar
		log.V(1).Infof("Geneve device already exists")
		existing, err := netlink.LinkByName(geneve.Name)
		if err != nil {
			return nil, err
		}

		incompat := geneveLinksIncompat(geneve, existing)
		if incompat == "" {
			log.V(1).Infof("Returning existing device")
			return existing.(*netlink.Geneve), nil
		}

		// delete existing
		log.Warningf("%q already exists with incompatable configuration: %v; recreating device", geneve.Name, incompat)
		if err = netlink.LinkDel(existing); err != nil {
			return nil, fmt.Errorf("failed to delete interface: %v", err)
		}

		// create new
		if err = netlink.LinkAdd(geneve); err != nil {
			return nil, fmt.Errorf("failed to create geneve interface: %v", err)
		}
	} else if err != nil {
		return nil, err
	}

	ifindex := geneve.Index
	link, err := netlink.LinkByIndex(geneve.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created geneve device with index %v", ifindex)
	}

	var ok bool
	if geneve, ok = link.(*netlink.Geneve); !ok {
		return nil, fmt.Errorf("created geneve device with index %v is not geneve", ifindex)
	}

	return geneve, nil
}

func (dev *geneveDevice) Configure(ipa ip.IP4Net, flannelnet ip.IP4Net) error {
	if err := ip.EnsureV4AddressOnLink(ipa, flannelnet, dev.link); err != nil {
		return fmt.Errorf("failed to ensure address of interface %s: %s", dev.link.Attrs().Name, err)
	}

	if err := netlink.LinkSetUp(dev.link); err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	return nil
}

func (dev *geneveDevice) ConfigureIPv6(ipn ip.IP6Net, flannelnet ip.IP6Net) error {
	if err := ip.EnsureV6AddressOnLink(ipn, flannelnet, dev.link); err != nil {
		return fmt.Errorf("failed to ensure v6 address of interface %s: %w", dev.link.Attrs().Name, err)
	}

	if err := netlink.LinkSetUp(dev.link); err != nil {
		return fmt.Errorf("failed to set v6 interface %s to UP state: %w", dev.link.Attrs().Name, err)
	}

	return nil
}

func (dev *geneveDevice) MACAddr() net.HardwareAddr {
	return dev.link.HardwareAddr
}

type neighbor struct {
	MAC net.HardwareAddr
	IP  ip.IP4
	IP6 *ip.IP6
}

func (dev *geneveDevice) AddFDB(n neighbor) error {
	log.V(4).Infof("calling AddFDB: %v, %v", n.IP, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) AddV6FDB(n neighbor) error {
	log.V(4).Infof("calling AddV6FDB: %v, %v", n.IP6, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) DelFDB(n neighbor) error {
	log.V(4).Infof("calling DelFDB: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) DelV6FDB(n neighbor) error {
	log.V(4).Infof("calling DelV6FDB: %v, %v", n.IP6, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) AddARP(n neighbor) error {
	log.V(4).Infof("calling AddARP: %v, %v", n.IP, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) AddV6ARP(n neighbor) error {
	log.V(4).Infof("calling AddV6ARP: %v, %v", n.IP6, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) DelARP(n neighbor) error {
	log.V(4).Infof("calling DelARP: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *geneveDevice) DelV6ARP(n neighbor) error {
	log.V(4).Infof("calling DelV6ARP: %v, %v", n.IP6, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func geneveLinksIncompat(l1, l2 netlink.Link) string {
	if l1.Type() != l2.Type() {
		return fmt.Sprintf("link type: %v vs %v", l1.Type(), l2.Type())
	}

	v1 := l1.(*netlink.Geneve)
	v2 := l2.(*netlink.Geneve)

	if v1.ID != v2.ID {
		return fmt.Sprintf("vni: %v vs %v", v1.ID, v2.ID)
	}

	return ""
}
