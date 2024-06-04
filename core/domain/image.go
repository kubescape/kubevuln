package domain

import "time"

type RawImageManifest struct {
	Config         string       `json:"config"`
	ImageID        string       `json:"imageID"`
	ManifestDigest string       `json:"manifestDigest"`
	ImageSize      int64        `json:"imageSize"`
	Layers         []ImageLayer `json:"layers"`
}

type ImageConfig struct {
	Architecture string         `json:"architecture"`
	OS           string         `json:"os"`
	History      []ImageHistory `json:"history"`
}

type ImageHistory struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	EmptyLayer bool      `json:"empty_layer"`
}

type ImageLayer struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}
