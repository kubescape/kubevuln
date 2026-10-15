package vexbatch

import (
	"fmt"
	"strings"

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

type documentKey struct {
	format Format
	path   string
}

// normalizeDocuments canonicalizes document formats, rejects unusable paths,
// and removes repeated references to the same file and format. It preserves
// first-seen order so applying a batch remains deterministic.
func normalizeDocuments(documents []Document) (map[Format][]Document, []Format, error) {
	groups := make(map[Format][]Document)
	var order []Format
	seen := make(map[documentKey]struct{}, len(documents))

	for i, document := range documents {
	for _, document := range documents {
		format := Format(strings.ToLower(strings.TrimSpace(string(document.Format))))
		switch format {
		case FormatOpenVEX, FormatCSAF:
		default:
			return nil, nil, fmt.Errorf(
				"unsupported VEX format %q",
				document.Format,
			)
		}

		if strings.TrimSpace(document.Path) == "" {
			return nil, nil, fmt.Errorf("VEX document %d has an empty path", i)
		}

		key := documentKey{format: format, path: document.Path}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		if _, exists := groups[format]; !exists {
			order = append(order, format)
		}
		groups[format] = append(groups[format], Document{
			Format: format,
			Path:   document.Path,
		})
	}

	return groups, order, nil
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

	groups, order, err := normalizeDocuments(documents)
	if err != nil {
		return matches, ignoredMatches, err
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
