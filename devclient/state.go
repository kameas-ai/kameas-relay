// Package devclient is the device-side client used by the remotectl CLI
// and the integration tests: QR pairing, session establishment (with
// mailbox drain and the two-regime seq acceptance), the live envelope
// stream, and the two-valued remote approval surface.
//
// It is a device-side test instrument: it holds keys by design and is
// forbidden to relay code by the deny-list.
package devclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kameas-ai/kameas-relay/e2ekit"
)

// State is the persisted device-side pairing record — the analogue of
// the iOS Keychain entry. Stored as JSON, file mode 0600 (dir 0700).
type State struct {
	RelayOrigin string `json:"relay_origin"`
	Sub         string `json:"sub"`
	HostID      string `json:"host_id"` // 22ch wire
	HostPK      string `json:"host_pk"` // 43ch wire
	HostName    string `json:"host_name"`
	DeviceID    string `json:"device_id"`
	DevPK       string `json:"dev_pk"`
	DevSK       string `json:"dev_sk"`
	ChannelID   string `json:"channel_id"`
	DeviceName  string `json:"device_name"`

	// Sequence high-water marks. Loss is fail-closed by design (N5):
	// there is deliberately no reset affordance anywhere in this tool.
	D2HLastSent uint64 `json:"d2h_last_sent"`
	H2DLastSeen uint64 `json:"h2d_last_seen"`

	dir string // save location (set by Load/Save)
}

const stateFile = "state.json"

// Load reads the device state from dir.
func Load(dir string) (*State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, fmt.Errorf("devclient: corrupt state: %w", err)
	}
	st.dir = dir
	return st, nil
}

// Save writes the state to dir (0700) as state.json (0600).
func (s *State) Save(dir string) error {
	if dir == "" {
		dir = s.dir
	}
	if dir == "" {
		return nil // ephemeral state (demo mode)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, stateFile)); err != nil {
		return err
	}
	s.dir = dir
	return nil
}

// keys decodes the binary fields.
func (s *State) keys() (hostID, deviceID, channel [16]byte, hostPK, devPK, devSK [32]byte, err error) {
	get := func(v string, n int) []byte {
		if err != nil {
			return nil
		}
		var raw []byte
		raw, err = e2ekit.DecodeBin(v, n)
		return raw
	}
	copy(hostID[:], get(s.HostID, 16))
	copy(deviceID[:], get(s.DeviceID, 16))
	copy(channel[:], get(s.ChannelID, 16))
	copy(hostPK[:], get(s.HostPK, 32))
	copy(devPK[:], get(s.DevPK, 32))
	copy(devSK[:], get(s.DevSK, 32))
	if err != nil {
		err = fmt.Errorf("devclient: corrupt state fields: %w", err)
	}
	return
}
