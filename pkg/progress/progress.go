package progress

import (
	"time"

	"github.com/projectdiscovery/gologger"
	"main/pkg/scanner"
)

func Start(scn *scanner.Scanner) {
	go func() {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()

		prevPackets := uint64(0)
		for range tick.C {
			totalPackets, _ := scn.Stats().GetCounter("total")
			packets, _ := scn.Stats().GetCounter("packets")
			if packets > prevPackets {
				gologger.Info().Msgf("Progress: %3.0f %% (%d/%d packets)\n", float64(packets)*100/float64(totalPackets), packets, totalPackets)
				prevPackets = packets
			}
		}
	}()
}
