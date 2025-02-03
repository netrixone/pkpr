package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/projectdiscovery/gologger"
	"main/pkg/monitor"
	"main/pkg/progress"
	"main/pkg/scanner"
	"main/pkg/whitelist"
)

const (
	version = "1.2"
	banner  = "PKPR - Port monitoring in Golang v" + version + "\n\n"
)

func main() {
	var err error

	// Parse the command line args.
	options := scanner.ParseOptions()
	if options.RunnerOptions.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	if !options.RunnerOptions.Silent {
		fmt.Print(banner)
	}

	// Load a whitelist if requested.
	var wl whitelist.Whitelist
	if options.Whitelist != "" {
		wl, err = whitelist.Load(options.Whitelist)
		if err != nil {
			gologger.Fatal().Msgf("Whitelist loading failed: %s\n", err.Error())
		}
	} else {
		wl = whitelist.Empty
	}

	// Init the scanner.
	scn, err := scanner.NewScanner(options)
	if err != nil {
		gologger.Fatal().Msgf("Scanner init failed: %s\n", err.Error())
	}
	defer scn.Close()

	// Init the monitor.
	mon := monitor.New(wl)
	scn.OnResult = mon.Evaluate
	mon.OnAlert = func(alert *monitor.Alert) {
		if alert.Severity == monitor.SeverityWarn {
			gologger.Warning().Msgf("%s\n", alert)
		} else {
			gologger.Error().Msgf("%s\n", alert)
		}
	}

	// Setup progressbar.
	progress.Start(scn)

	// Run it.
	if err = scn.Run(context.TODO()); err != nil {
		gologger.Fatal().Msgf("Scan failed: %s\n", err.Error())
	}

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			mon.Close()
			os.Exit(1)
		}
	}()

	mon.Close()

	// Write the output to file if requested.
	if options.RunnerOptions.Output != "" {
		if err := mon.WriteAsJson(options.RunnerOptions.Output); err != nil {
			gologger.Fatal().Msgf("Could not save results: %s\n", err.Error())
		}
		gologger.Info().Msgf("Results written to %q.\n", options.RunnerOptions.Output)
	}
}
