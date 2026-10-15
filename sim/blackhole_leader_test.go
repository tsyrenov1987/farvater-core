package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// Field case 15.10 (iPhone, home Wi-Fi): the leader at start connects but
// never answers, and so do most of the other paths of the catalogue; one
// direct path and two relays carry. One app (Instagram) talks to a handful of
// hosts. In the field the leader stayed 9–16 minutes.
func scBlackholeLeader(seed uint64) Scenario {
	paths := []PathModel{{ID: "rux14", SNI: "x4.ru", IP: "10.9.0.2", Rail: "xhttp", RTTMs: 40, BlackholeFrom: 1}}
	for i := 0; i < 12; i++ {
		rail := "xhttp"
		if i%3 == 0 {
			rail = "grpc"
		}
		paths = append(paths, PathModel{ID: "cdnv" + itoa(i), SNI: "x" + itoa(i) + ".ru", IP: "10.9.0.3", Rail: rail, RTTMs: 35, BlackholeFrom: 1})
	}
	paths = append(paths,
		PathModel{ID: "nl1", SNI: "eu11.example", IP: "10.9.1.1", Rail: "reality", RTTMs: 60, GoodputBps: 3_000_000},
		PathModel{ID: "rux21", SNI: "x9.ru", IP: "10.9.0.1", Rail: "xhttp", RTTMs: 45, GoodputBps: 2_000_000},
		PathModel{ID: "rux26", SNI: "x11.ru", IP: "10.9.0.1", Rail: "xhttp", RTTMs: 45, GoodputBps: 2_000_000})
	return Scenario{Name: "blackhole leader, few hosts", Seed: seed, Paths: paths,
		Work: Workload{N: 900, DurationMs: 30 * minute, BurstProb: 0.3, BurstSize: 4, Hosts: 6}}
}

func firstLeave(b *brain.Brain, from string) int64 {
	for _, e := range b.J.Entries() {
		if e.Path != from && (e.Act == "lead_init" || e.Act == "lead_switch" || e.Act == "lead_stall") {
			return e.AtMs
		}
		if e.Path == from && e.Act == "lead_trip" {
			return e.AtMs
		}
	}
	return -1
}

// The black-holed leader must go within two minutes, not after the
// destination quarantine has hidden its failures for many more.
func TestBlackholeLeaderLeavesFast(t *testing.T) {
	for seed := uint64(1); seed <= 8; seed++ {
		sc := scBlackholeLeader(seed)
		ours, b := runOurs(sc)
		at := firstLeave(b, "rux14")
		t.Logf("seed %d: rux14 left at %.1f min, leader=%s dropped=%d success(0-5m)=%.2f success(all)=%.2f",
			seed, float64(at)/60000, b.Leader(), b.Dropped, ours.SuccessRate(0, 5*minute), ours.SuccessRate(0, 1<<62))
		if at < 0 || at > 2*minute {
			t.Errorf("seed %d: black-holed leader stayed %.1f min", seed, float64(at)/60000)
		}
	}
}

func TestHalfBlackholeLeaderProbe(t *testing.T) {
	for _, prob := range []float64{0.2, 0.35, 0.5} {
		for seed := uint64(1); seed <= 4; seed++ {
			sc := scBlackholeLeader(seed)
			sc.Paths[0].BlackholeFrom, sc.Paths[0].BlackholeProb, sc.Paths[0].GoodputBps = 0, prob, 2_000_000
			ours, b := runOurs(sc)
			at := firstLeave(b, "rux14")
			t.Logf("p=%.2f seed %d: rux14 left at %.1f min, leader=%s fails(0-10m)=%.2f", prob, seed, float64(at)/60000, b.Leader(), 1-ours.SuccessRate(0, 10*minute))
		}
	}
}
