package leakageattack

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/NudgeArtifact/private-recs/share"
)

// MovieLensFile is where the ratings of MovieLens 100K are expected, as
// unpacked from https://files.grouplens.org/datasets/movielens/ml-100k.zip.
// Each line holds a user id, a movie id, a rating from 1 to 5 and a timestamp,
// separated by tabs.
const MovieLensFile = "data/ml-100k/u.data"

// MovieLens builds a 0/1 ratings matrix from the MovieLens 100K ratings in the
// file 'path'. Every rating counts as a 1, whatever its value, as in Nudge's
// evaluation on MovieLens. With 'movies' = 0, the matrix has all 943 users and
// all 1,682 movies. Otherwise it keeps only the 'movies' most-rated movies,
// ties broken by the lower movie id, and the users who rated at least one of
// them. Rows follow the order of the user ids and columns that of the movie ids.
func MovieLens(path string, movies int) (*share.Matrix[uint64], error) {
	// reading the user and movie of every rating
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type rating struct{ user, movie int }
	var ratings []rating
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			return nil, fmt.Errorf("bad line in %s: %q", path, scanner.Text())
		}
		user, err1 := strconv.Atoi(fields[0])
		movie, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad line in %s: %q", path, scanner.Text())
		}
		ratings = append(ratings, rating{user, movie})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// choosing the movies to keep: all of them, or the most-rated ones
	count := map[int]int{}
	for _, r := range ratings {
		count[r.movie]++
	}
	var kept []int
	for movie := range count {
		kept = append(kept, movie)
	}
	if movies > 0 {
		sort.Slice(kept, func(a, b int) bool {
			if count[kept[a]] != count[kept[b]] {
				return count[kept[a]] > count[kept[b]]
			}
			return kept[a] < kept[b]
		})
		kept = kept[:movies]
	}
	sort.Ints(kept)
	column := map[int]uint64{}
	for j, movie := range kept {
		column[movie] = uint64(j)
	}

	// keeping the users who rated at least one of the kept movies
	keptUser := map[int]bool{}
	for _, r := range ratings {
		if _, ok := column[r.movie]; ok {
			keptUser[r.user] = true
		}
	}
	var users []int
	for user := range keptUser {
		users = append(users, user)
	}
	sort.Ints(users)
	row := map[int]uint64{}
	for i, user := range users {
		row[user] = uint64(i)
	}

	// filling in a 1 for every rating of a kept movie
	U := share.MatrixZeros[uint64](uint64(len(users)), uint64(len(kept)))
	one := uint64(1)
	for _, r := range ratings {
		if j, ok := column[r.movie]; ok {
			U.Set(row[r.user], j, &one)
		}
	}
	return U, nil
}

// MovieLensVictims lists the victims of the MovieLens matrices by row: the
// users with the fewest ratings, at the first quartile, the median, the third
// quartile and with the most ratings. They rated 20, 33, 65, 148 and 737 items
// in ml100k, and 1, 8, 14, 23 and 39 items in ml100k-40.
var MovieLensVictims = map[string][]uint64{
	"ml100k":    {18, 376, 53, 600, 404},
	"ml100k-40": {819, 609, 671, 157, 414},
}
