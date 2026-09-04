package vexbatch

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
)

type Format string

const (
	FormatOpenVEX Format = "openvex"
	FormatCSAF    Format = "csaf"
)

type Document struct {
	Format Format
	Path   string
}

func Apply(
	documents []Document,
	pkgContext *pkg.Context,
	matches *match.Matches,
	ignoredMatches []match.IgnoredMatch,
	ignoreRules []match.IgnoreRule,
) (*match.Matches, []match.IgnoredMatch, error) {
	if len(documents) == 0 {
		return matches, ignoredMatches, nil
	}

	groups := make(map[Format][]Document)
	var order []Format

	for _, document := range documents {
		switch document.Format {
		case FormatOpenVEX, FormatCSAF:
		default:
			return matches, ignoredMatches, fmt.Errorf(
				"unsupported VEX format %q",
				document.Format,
			)
		}

		if _, exists := groups[document.Format]; !exists {
			order = append(order, document.Format)
		}

		groups[document.Format] = append(groups[document.Format], document)
	}

	for _, format := range order {
		group := groups[format]

		paths := make([]string, 0, len(group))
		for _, document := range group {
			paths = append(paths, document.Path)
		}

		processor, err := vex.NewProcessor(vex.ProcessorOptions{
			Documents:   paths,
			IgnoreRules: ignoreRules,
		})
		if err != nil {
			return matches, ignoredMatches, fmt.Errorf(
				"creating VEX processor for format %q: %w",
				format,
				err,
			)
		}

		matches, ignoredMatches, err = processor.ApplyVEX(
			pkgContext,
			matches,
			ignoredMatches,
		)
		if err != nil {
			return matches, ignoredMatches, fmt.Errorf(
				"applying VEX documents for format %q: %w",
				format,
				err,
			)
		}
	}

	return matches, ignoredMatches, nil
}
