package dns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/lxc/incus/v6/internal/ports"
	"github.com/lxc/incus/v6/internal/server/db"
	internalUtil "github.com/lxc/incus/v6/internal/util"
	"github.com/lxc/incus/v6/shared/logger"
	"github.com/lxc/incus/v6/shared/revert"
)

// ZoneRetriever is a function which fetches a DNS zone.
type ZoneRetriever func(name string, full bool) (*Zone, error)

// Server represents a DNS server instance.
type Server struct {
	tcpDNS *dns.Server
	udpDNS *dns.Server

	// External dependencies.
	db            *db.Cluster
	zoneRetriever ZoneRetriever

	// Internal state (to handle reconfiguration).
	address string

	// Internal state to handle restarts.
	restart        chan struct{}
	restartPending bool

	mu sync.Mutex
}

// NewServer returns a new server instance.
func NewServer(db *db.Cluster, retriever ZoneRetriever) *Server {
	// Setup new struct.
	s := &Server{db: db, zoneRetriever: retriever}
	return s
}

// Start sets up the DNS listener.
func (s *Server) Start(address string) error {
	// Locking.
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.start(address)
}

func (s *Server) start(address string) error {
	if s.address != "" {
		return nil
	}

	// Set default port if needed.
	address = internalUtil.CanonicalNetworkAddress(address, ports.DNSDefaultPort)

	// Setup the handler.
	handler := dnsHandler{}
	handler.server = s

	// Spawn the DNS server.
	s.tcpDNS = &dns.Server{Addr: address, Net: "tcp", Handler: handler}
	go func() {
		err := s.tcpDNS.ListenAndServe()
		if err != nil {
			logger.Errorf("Failed to bind TCP DNS address %q: %v", address, err)
			s.restartFailed()
		}
	}()

	s.udpDNS = &dns.Server{Addr: address, Net: "udp", Handler: handler}
	go func() {
		err := s.udpDNS.ListenAndServe()
		if err != nil {
			logger.Errorf("Failed to bind UDP DNS address %q: %v", address, err)
			s.restartFailed()
		}
	}()

	// Record the address.
	s.address = address

	// TSIG handling.
	err := s.updateTSIG()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) restartFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.restartPending {
		return
	}

	s.stop()

	s.restart = make(chan struct{})
	s.restartPending = true

	go func() {
		restartTimer := time.NewTimer(time.Second * 10)
		select {
		case <-restartTimer.C:
			s.mu.Lock()
			// If the restart was cancelled in the meantime then s.restart is closed and writing to it would panic.
			if s.restartPending {
				s.restart <- struct{}{}
			}

			s.mu.Unlock()
		}
	}()

	cleanupTimer := time.NewTimer(time.Second * 20)

	go func() {
		select {
		case <-s.restart:
			s.mu.Lock()
			var err error

			// Only start if the restart was not cancelled.
			if s.restartPending {
				err = s.start(s.address)
			}

			s.mu.Unlock()

			if err != nil {
				logger.Errorf("Failed to start DNS server: %v", err)
				s.restartFailed()
			}

		case <-cleanupTimer.C:
			// Restart was cancelled before the select.
		}
	}()
}

// Stop tears down the DNS listener.
func (s *Server) Stop() error {
	// Locking.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.restart != nil {
		close(s.restart)
		s.restartPending = false
	}

	s.stop()

	return nil
}

func (s *Server) stop() {
	// Skip if no instance.
	if s.address == "" {
		return
	}

	// Stop the listener.
	_ = s.tcpDNS.Shutdown()
	_ = s.udpDNS.Shutdown()

	// Unset the address.
	s.address = ""
}

// Reconfigure updates the listener with a new configuration.
func (s *Server) Reconfigure(address string) error {
	// Locking.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.restart != nil {
		close(s.restart)
		s.restart = nil
	}

	return s.reconfigure(address)
}

func (s *Server) reconfigure(address string) error {
	// Get the old address.
	oldAddress := s.address

	// Setup reverter.
	reverter := revert.New()
	defer reverter.Fail()

	// Stop the listener.
	s.stop()

	// Check if we should start.
	if address != "" {
		// Restore old address on failure.
		reverter.Add(func() { _ = s.start(oldAddress) })

		// Start the listener with the new address.
		err := s.start(address)
		if err != nil {
			return err
		}
	}

	// All done.
	reverter.Success()

	return nil
}

// UpdateTSIG fetches all TSIG keys and loads them into the DNS server.
func (s *Server) UpdateTSIG() error {
	// Locking.
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.updateTSIG()
}

func (s *Server) updateTSIG() error {
	// Skip if no instance.
	if s.tcpDNS == nil || s.udpDNS == nil || s.db == nil {
		return nil
	}

	var secrets map[string]string

	err := s.db.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		var err error

		// Get all the secrets.
		secrets, err = tx.GetNetworkZoneKeys(ctx)

		return err
	})
	if err != nil {
		return err
	}

	// Apply to the DNS servers.
	s.tcpDNS.TsigSecret = secrets
	s.udpDNS.TsigSecret = secrets

	return nil
}
