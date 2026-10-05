package brain

// Entry is one explainable decision.
type Entry struct {
	AtMs int64
	Act  string
	Why  string
	Path string
}

// Journal keeps the last N decisions.
type Journal struct {
	entries []Entry
	max     int
}

// NewJournal returns a ring journal of at most max entries.
func NewJournal(max int) *Journal { return &Journal{max: max} }

// Add appends an entry.
func (j *Journal) Add(at int64, act, why, path string) {
	j.entries = append(j.entries, Entry{at, act, why, path})
	if len(j.entries) > j.max {
		j.entries = j.entries[len(j.entries)-j.max:]
	}
}

// Entries returns a copy of the journal.
func (j *Journal) Entries() []Entry { return append([]Entry(nil), j.entries...) }

// Count returns how many entries carry the given act.
func (j *Journal) Count(act string) int {
	n := 0
	for _, e := range j.entries {
		if e.Act == act {
			n++
		}
	}
	return n
}
