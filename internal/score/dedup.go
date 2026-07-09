package score

// Dedup groups results by DedupKey, keeps the highest-scoring result per group,
// and sets Count to reflect how many duplicates were collapsed.
func Dedup(results []ScoredResult) []ScoredResult {
	type entry struct {
		best  ScoredResult
		count int
	}

	// Use a map keyed by DedupKey and a slice to preserve first-seen order.
	groups := make(map[DedupKey]*entry)
	var order []DedupKey

	for _, r := range results {
		key := DedupKey{
			StatusCode:    r.StatusCode,
			ContentLength: r.ContentLength,
			BodyHash:      r.BodyHash,
		}
		if e, ok := groups[key]; ok {
			e.count++
			if r.Score > e.best.Score {
				e.best = r
			}
		} else {
			groups[key] = &entry{best: r, count: 1}
			order = append(order, key)
		}
	}

	deduped := make([]ScoredResult, 0, len(order))
	for _, key := range order {
		e := groups[key]
		e.best.Count = e.count
		deduped = append(deduped, e.best)
	}
	return deduped
}

// FilterByStatus returns only results matching the given HTTP status code.
func FilterByStatus(results []ScoredResult, statusCode int) []ScoredResult {
	var filtered []ScoredResult
	for _, r := range results {
		if r.StatusCode == statusCode {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// FilterUnique returns only results whose status code OR body hash differ
// from the baseline values. This strips out results that are identical to the
// blocked response.
func FilterUnique(results []ScoredResult, baselineStatus int, baselineBodyHash string) []ScoredResult {
	var filtered []ScoredResult
	for _, r := range results {
		if r.StatusCode != baselineStatus || r.BodyHash != baselineBodyHash {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
