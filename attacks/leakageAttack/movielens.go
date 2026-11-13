package leakageattack

// MovieLensVictims lists the victims of the MovieLens matrices by row: the
// users with the fewest ratings, at the first quartile, the median, the third
// quartile and with the most ratings. They rated 20, 33, 65, 148 and 737 items
// in ml100k, and 1, 8, 14, 23 and 39 items in ml100k-40.
var MovieLensVictims = map[string][]uint64{
	"ml100k":    {18, 376, 53, 600, 404},
	"ml100k-40": {819, 609, 671, 157, 414},
}
