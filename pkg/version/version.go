package version

var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

func FullVersion() string {
	return Version + " (" + GitCommit + ") built " + BuildDate
}
