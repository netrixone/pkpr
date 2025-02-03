package scanner

import (
	"errors"
	"os"
	"time"

	"github.com/netrixone/naabu-probe/pkg/runner"
	"github.com/netrixone/naabu-probe/pkg/scan"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Options struct {
	RunnerOptions *runner.Options
	Whitelist     string
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{RunnerOptions: &runner.Options{Ports: runner.Full}}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`PKPR :: Port scanner that keeps track of your open ports`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.RunnerOptions.Host, "host", "h", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.Whitelist, "whitelist", "w", "", "YAML file with definition of whitelisted ports"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.RunnerOptions.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.RunnerOptions.TopPorts, "tp", "top-ports", "", "top ports to scan (default full) [full,100,1000]"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.RunnerOptions.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.RunnerOptions.Rate, "rate", runner.DefaultRateSynScan, "packets to send per second"),
		flagSet.IntVar(&options.RunnerOptions.PerHostConcurrency, "host-concurrency", runner.DefaultHostConcurrency, "max number of concurrent packets for each host"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.RunnerOptions.Output, "output", "o", "", "file to write output to (optional)"),
		flagSet.BoolVar(&options.RunnerOptions.CSV, "csv", false, "write output in csv format"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&cfgFile, "config", "", "path to the PKPR configuration file (default $HOME/.config/pkpr/config.yaml)"),
		flagSet.StringSliceVarP(&options.RunnerOptions.IPVersion, "iv", "ip-version", []string{scan.IPv4}, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.RunnerOptions.ScanType, "s", "scan-type", runner.ConnectScan, "type of port scan (SYN/CONNECT)"),
		flagSet.BoolVarP(&options.RunnerOptions.InterfacesList, "il", "interface-list", false, "list available interfaces and public ip"),
		flagSet.StringVarP(&options.RunnerOptions.Interface, "i", "interface", "", "network Interface to use for port scan"),
		flagSet.StringVar(&options.RunnerOptions.Resolvers, "r", "", "list of custom resolver dns resolution (comma separated or from file)"),
		flagSet.StringVar(&options.RunnerOptions.Proxy, "proxy", "", "socks5 proxy (ip[:port] / fqdn[:port]"),
		flagSet.StringVar(&options.RunnerOptions.ProxyAuth, "proxy-auth", "", "socks5 proxy authentication (username:password)"),
		flagSet.DurationVarP(&options.RunnerOptions.InputReadTimeout, "input-read-timeout", "irt", 3*time.Minute, "timeout on input read"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.RunnerOptions.Retries, "retries", runner.DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.DurationVar(&options.RunnerOptions.Timeout, "timeout", runner.DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
		flagSet.IntVar(&options.RunnerOptions.WarmUpTime, "warm-up-time", 2, "time in seconds between scan phases"),
		flagSet.BoolVar(&options.RunnerOptions.Verify, "verify", false, "validate the ports again with TCP verification"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.RunnerOptions.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&options.RunnerOptions.Debug, "debug", false, "display debugging information"),
		flagSet.BoolVarP(&options.RunnerOptions.Verbose, "v", "verbose", false, "display verbose output"),
		flagSet.BoolVarP(&options.RunnerOptions.NoColor, "nc", "no-color", false, "disable colors in CLI output"),
		flagSet.BoolVar(&options.RunnerOptions.Silent, "silent", false, "display only results in output"),
		flagSet.BoolVar(&options.RunnerOptions.Version, "version", false, "display version of PKPR"),
	)

	_ = flagSet.Parse()

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if options.RunnerOptions.HealthCheck {
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(options.RunnerOptions, flagSet))
		os.Exit(0)
	}

	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options.RunnerOptions.ConfigureOutput()

	// Show network configuration and exit if the user requested it
	if options.RunnerOptions.InterfacesList {
		err := runner.ShowNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Enable reverse PTR.
	options.RunnerOptions.ReversePTR = true

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.ValidateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func (o *Options) ValidateOptions() error {
	if o.RunnerOptions.Version || o.RunnerOptions.HealthCheck || o.RunnerOptions.InterfacesList {
		return nil
	}

	if o.Whitelist != "" {
		if info, err := os.Stat(o.Whitelist); err != nil {
			return errors.Join(errors.New("cannot use given input file"), err)
		} else if info.IsDir() {
			return errors.New("input file is a directory")
		}
	}

	return o.RunnerOptions.ValidateOptions()
}
