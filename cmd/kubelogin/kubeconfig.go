package main

import (
	"encoding/base64"
	"fmt"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"io/ioutil"
)

type KubeConfig struct {
	ClusterName string
	AuthProviderName string
	ContextName string
	AuthInfoName string
	Issuer_url string
	Id_token string
	Refresh_token string
	ConfigFile string
}

func (c *KubeConfig) CreateConfig() error {
	configAccess := clientcmd.NewDefaultPathOptions()
	c.ConfigFile = configAccess.GetDefaultFilename();
	config, error := clientcmd.LoadFromFile(c.ConfigFile)
	if error != nil {
		//println("generating: " + c.ConfigFile)
		config = clientcmdapi.NewConfig()
	} else {
		//println("updating: " + configAccess.GetDefaultFilename())
	}
	cluster, exists := config.Clusters[c.ClusterName]
	if !exists {
		cluster = clientcmdapi.NewCluster()
		config.Clusters[c.ClusterName] = cluster
	}

	cluster.Server = "https://10.245.251.155:6443"
	caPath := "/etc/kubernetes/ca.pem"
	apiCaPath := "/etc/kubernetes/pki/ca.crt"
	cluster.CertificateAuthorityData, _ = ioutil.ReadFile(apiCaPath)
	cluster.InsecureSkipTLSVerify = false
	cluster.CertificateAuthority = ""
	authInfo, exists := config.AuthInfos[c.AuthInfoName]
	if !exists {
		authInfo = clientcmdapi.NewAuthInfo()
		config.AuthInfos[c.AuthInfoName] = authInfo
	}
	caData, _ := ioutil.ReadFile(caPath)
	authProviderConfig := map[string]string{
		"client-id":                      "example-app",
		"client-secret":                  "ZXhhbXBsZS1hcHAtc2VjcmV0",
		"extra-scopes":                   "groups",
		"id-token":                       c.Id_token,
		"idp-certificate-authority-data": base64.StdEncoding.EncodeToString(caData),
		"idp-issuer-url":                 c.Issuer_url,
		"refresh-token":                  c.Refresh_token,
	}
	authInfo.AuthProvider = &clientcmdapi.AuthProviderConfig{
		Name:   c.AuthProviderName,
		Config: authProviderConfig,
	}
	context, exists := config.Contexts[c.ContextName]
	if !exists {
		context = clientcmdapi.NewContext()
		config.Contexts[c.ContextName] = context
	}
	context.Cluster = c.ClusterName
	context.AuthInfo = c.AuthInfoName

	config.CurrentContext = c.ContextName
	error = clientcmd.ModifyConfig(configAccess, *config, true)
	if error != nil {
		fmt.Println(error)
	}
	return error
}