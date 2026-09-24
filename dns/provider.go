package dns

type Provider interface {
	Records() ([]Record, error)
}
