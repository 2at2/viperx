package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/viper"

	"github.com/sagikazarmark/viperx/remote"
)

// nolint: gochecknoinits
func init() {
	remote.RegisterConfigProvider("vault", NewConfigProvider())
}

// ConfigProvider implements reads configuration from Hashicorp Vault.
type ConfigProvider struct {
	clients map[string]*api.Client
}

// NewConfigProvider returns a new ConfigProvider.
func NewConfigProvider() *ConfigProvider {
	return &ConfigProvider{
		clients: make(map[string]*api.Client),
	}
}

func (p ConfigProvider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	client, ok := p.clients[rp.Endpoint()]
	if !ok {
		endpoint := rp.Endpoint()
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse provider endpoint")
		}

		config := api.DefaultConfig()
		config.Address = u.String()
		c, err := api.NewClient(config)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to create vault api client")
		}

		token := os.Getenv("VAULT_TOKEN")
		if len(token) == 0 {
			return nil, fmt.Errorf("undefined env variable VAULT_TOKEN")
		}

		c.SetToken(token)

		client = c
		p.clients[endpoint] = c
	}

	secret, err := client.Logical().Read(rp.Path())
	if err != nil {
		return nil, errors.WrapIf(err, "failed to read secret")
	}

	if secret == nil {
		return nil, errors.Errorf("source not found: %s", rp.Path())
	}

	if secret.Data == nil && secret.Warnings != nil {
		return nil, errors.Errorf("source: %s errors: %v", rp.Path(), secret.Warnings)
	}

	nestedMap := toSearchableMap(secret.Data)

	b, err := json.Marshal(nestedMap)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to json encode secret")
	}

	return bytes.NewReader(b), nil
}

func (p ConfigProvider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	return nil, errors.New("watch is not implemented for the vault config provider")
}

func (p ConfigProvider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	panic("watch channel is not implemented for the vault config provider")
}

func toSearchableMap(source map[string]interface{}) map[string]interface{} {
	nestedMap := make(map[string]interface{})
	for k, v := range source {
		if !strings.Contains(k, ".") {
			nestedMap[k] = v
		} else {
			parts := strings.Split(k, ".")
			l := len(parts)

			referencedMap := nestedMap
			for i, p := range parts {
				last := l == i+1

				if _, ok := referencedMap[p]; ok {
					if last {
						referencedMap[p] = v
					} else {
						referencedMap = referencedMap[p].(map[string]interface{})
					}
				} else {
					if last {
						referencedMap[p] = v
					} else {
						referencedMap[p] = make(map[string]interface{})
						nestedMap = referencedMap
						referencedMap = referencedMap[p].(map[string]interface{})
					}
				}
			}
		}
	}

	return nestedMap
}
