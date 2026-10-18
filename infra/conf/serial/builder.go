package serial

import (
	"context"
	"fmt"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/main/confloader"
)

// UseStrictJSON, when true, makes JSON config decoders skip the custom
// comment-stripping reader and parse input as strict RFC 8259 JSON.
//
// Enabled by setting the env variable xray.json.strict=true (or its normalized
// form XRAY_JSON_STRICT=true). Default false preserves backward-compatible
// behavior for human-edited configs that may contain comments or other
// JSON5/JSONC syntax.
var UseStrictJSON = platform.NewEnvFlag(platform.UseStrictJSON).GetValue(func() string { return "" }) == "true"

func MergeConfigFromFiles(files []*core.ConfigSource) (string, error) {
	c, err := mergeConfigs(files)
	if err != nil {
		return "", err
	}

	if j, ok := creflect.MarshalToJson(c, true); ok {
		return j, nil
	}
	return "", errors.New("marshal to json failed.")
}

func mergeConfigs(files []*core.ConfigSource) (*conf.Config, error) {
	cf := &conf.Config{}
	for i, file := range files {
		errors.LogInfo(context.Background(), "Reading config: ", file)
		r, err := confloader.LoadConfig(file.Name)
		if err != nil {
			return nil, errors.New("failed to read config: ", file).Base(err)
		}
		decoder := ReaderDecoderByFormat[file.Format]
		if file.Format == "json" && UseStrictJSON {
			decoder = DecodeJSONConfigStrict
		}
		c, err := decoder(r)
		if err != nil {
			return nil, errors.New("failed to decode config: ", file).Base(err)
		}
		if len(files) > 1 {
			switch file.Format {
			case "subscription", "sub", "subjson", "node-list":
				// These formats generate advisory tags starting at 001 in
				// every file. Scope them by input position before applying
				// the original merge rules, which replace equal tags.
				for j := range c.OutboundConfigs {
					c.OutboundConfigs[j].Tag = fmt.Sprintf("%s-file-%03d", c.OutboundConfigs[j].Tag, i+1)
				}
			}
		}
		if i == 0 {
			*cf = *c
			continue
		}
		cf.Override(c, file.Name)
	}
	return cf, nil
}

func BuildConfig(files []*core.ConfigSource) (*core.Config, error) {
	config, err := mergeConfigs(files)
	if err != nil {
		return nil, err
	}
	return config.Build()
}

type readerDecoder func(io.Reader) (*conf.Config, error)

var ReaderDecoderByFormat = make(map[string]readerDecoder)

func init() {
	ReaderDecoderByFormat["json"] = DecodeJSONConfig
	ReaderDecoderByFormat["yaml"] = DecodeYAMLConfig
	ReaderDecoderByFormat["toml"] = DecodeTOMLConfig
	ReaderDecoderByFormat["uri"] = DecodeURIConfig
	ReaderDecoderByFormat["node"] = DecodeNodeConfig
	ReaderDecoderByFormat["subscription"] = DecodeSubscriptionConfig
	ReaderDecoderByFormat["sub"] = DecodeSubscriptionConfig
	ReaderDecoderByFormat["subjson"] = DecodeNodeListJSONConfig
	ReaderDecoderByFormat["node-list"] = DecodeNodeListJSONConfig

	core.ConfigBuilderForFiles = BuildConfig
	core.ConfigMergedFormFiles = MergeConfigFromFiles
}
