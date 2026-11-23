package x

type Regress struct {
	Handler   interface{}
	Timeout   timeout
	Str       stringer
	Ints      integer
	Ok        bool
	Count     uint32
	Ratio     float64
	When      time.Time
	Ptr       *string
	List      []string
}
