package brain

import (
	"math"
	"math/rand/v2"
)

// gammaSample draws Gamma(k, 1) (Marsaglia–Tsang; boost for k < 1).
func gammaSample(rng *rand.Rand, k float64) float64 {
	if k < 1 {
		u := rng.Float64()
		if u == 0 {
			u = 1e-12
		}
		return gammaSample(rng, k+1) * math.Pow(u, 1/k)
	}
	d := k - 1.0/3
	c := 1 / math.Sqrt(9*d)
	for {
		x := rng.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rng.Float64()
		if u < 1-0.0331*x*x*x*x {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// BetaSample draws Beta(a, b).
func BetaSample(rng *rand.Rand, a, b float64) float64 {
	x := gammaSample(rng, a)
	y := gammaSample(rng, b)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}
