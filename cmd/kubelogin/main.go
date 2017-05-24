package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

const exampleAppState = "state"

type app struct {
	clientID     string
	clientSecret string
	redirectURI  string

	issuerURL string
	verifier  *oidc.IDTokenVerifier
	provider  *oidc.Provider
	server    *http.Server
	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool
	listenPort     int32

	client *http.Client
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func cmd() *cobra.Command {
	var (
		a       app
		rootCAs string
	)
	c := cobra.Command{
		Use:   "ocloud",
		Short: "An opc of oke",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("surplus arguments provided")
			}

			if rootCAs != "" {
				client, err := httpClientForRootCAs(rootCAs)
				if err != nil {
					return err
				}
				a.client = client
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			ctx := oidc.ClientContext(context.Background(), a.client)
			provider, err := oidc.NewProvider(ctx, a.issuerURL)
			if err != nil {
				return fmt.Errorf("Failed to query provider %q: %v", a.issuerURL, err)
			}

			var s struct {
				// What scopes does a provider support?
				//
				// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
				ScopesSupported []string `json:"scopes_supported"`
			}
			if err := provider.Claims(&s); err != nil {
				return fmt.Errorf("Failed to parse provider scopes_supported: %v", err)
			}

			if len(s.ScopesSupported) == 0 {
				// scopes_supported is a "RECOMMENDED" discovery claim, not a required
				// one. If missing, assume that the provider follows the spec and has
				// an "offline_access" scope.
				a.offlineAsScope = true
			} else {
				// See if scopes_supported has the "offline_access" scope.
				a.offlineAsScope = func() bool {
					for _, scope := range s.ScopesSupported {
						if scope == oidc.ScopeOfflineAccess {
							return true
						}
					}
					return false
				}()
			}

			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

			http.HandleFunc("/", a.handleCallback)
			authCodeURL := a.getAuthCodeURL(false)
			a.server = &http.Server{Addr: fmt.Sprintf(":%d", a.listenPort), Handler: nil}
			go func() {
				http.ListenAndServe(fmt.Sprintf(":%d", a.listenPort),nil);
			}()
			err = browser.OpenURL(authCodeURL)
			if (err == nil) {
				fmt.Printf("Your browser has been opened to visit: \n%s", authCodeURL)
				select{};
			} else {
				authCodeURL := a.getAuthCodeURL(true)
				fmt.Printf("error: %v", err)
				fmt.Printf("Go to the following link in your browser: \n%s\nEnter verification code:", authCodeURL)
				var code string
				var configFile string
				fmt.Scanln(&code)
				configFile, err = a.createConfig(ctx, code, "", "")
				if err != nil {
					fmt.Printf("Error when updating kubeconfig entry: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Printf("kubeconfig entry generated: %s\n", configFile)
					os.Exit(0)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&a.clientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&a.clientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	c.Flags().StringVar(&a.issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	c.Flags().Int32Var(&a.listenPort, "listenPort", 9999, "HTTP(S) port to listen at.")
	c.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	return &c
}

func (a *app) oauth2Config(scopes []string, isOOB bool) *oauth2.Config {
	var redirectURL string
	if (isOOB) {
		redirectURL = "urn:ietf:wg:oauth:2.0:oob"
	} else {
		redirectURL = fmt.Sprintf("http://localhost:%d/", a.listenPort)
	}
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  redirectURL,
	}
}

func (a *app) getAuthCodeURL(isOOB bool) string {
	var authCodeURL string
	scopes := []string{"openid", "profile", "email", "groups", "offline_access"}
	if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes, isOOB).AuthCodeURL(exampleAppState)
	} else {
		authCodeURL = a.oauth2Config(scopes, isOOB).AuthCodeURL(exampleAppState, oauth2.AccessTypeOffline)
	}
	return authCodeURL
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err        error
		code       string
		state      string
		refresh    string
		configFile string
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code = r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state = r.FormValue("state"); state != exampleAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
			return
		}
	case "POST":
		// Form request from frontend to refresh a token.
		refresh = r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}
	configFile, err = a.createConfig(ctx, code, state, refresh)
	if err != nil {
		fmt.Fprintf(w, "Error when updating kubeconfig entry: %v\n", err)
		fmt.Printf("Error when updating kubeconfig entry: %v\n", err)
	} else {
		fmt.Fprintf(w, "kubeconfig entry generated: %s\n", configFile)
		fmt.Printf("kubeconfig entry generated: %s\n", configFile)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	if err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func (a *app) createConfig(ctx context.Context, code string, state string, refresh string) (string, error) {
	var (
		err   error
		token *oauth2.Token
	)

	oauth2Config := a.oauth2Config(nil, false)
	if code != "" {
		token, err = oauth2Config.Exchange(ctx, code)
	} else if refresh != "" {
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	} else {
		return "", errors.New("oauth2: code, state and refresh token are all not set")
	}

	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to get token: %v", err))
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token in token response")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to verify ID token: %v", err))
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")

	fmt.Printf("claims: %s\nrawIDToken: %s\nRefreshToken: %s\n", string(buff.Bytes()), rawIDToken, token.RefreshToken)

	config := &KubeConfig{
		ClusterName:      "oidc",
		AuthProviderName: "oidc",
		ContextName:      "oidc",
		AuthInfoName:     "oidcUser",
		Issuer_url:       a.issuerURL,
		Id_token:         rawIDToken,
		Refresh_token:    token.RefreshToken}
	err = config.CreateConfig()
	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to update KubeConfig file: %v", err))
	} else {
		return config.ConfigFile, nil
	}
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
